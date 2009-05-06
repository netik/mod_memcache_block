/* mod_memcached_block
 *
 * Module to block users by CIDR blocks stored in memcache.
 *
 * Designed for high traffic loads, the module occasionally asks memcache
 * for the blocklist and does not poll on every request.
 *
 * It also includes rate-limiting code that can rate limit access baesd
 * on HTTP Response Codes.
 *
 * CIDR matching code derived from grepcidr 1.3 by Jem Berkes, SysDesign
 * http://www.pc-tools.net/unix/grepcidr/
 *
 * memcache values may take the form 'x.x.x.x', 'x.x.x.x/N', or ranges
 * like 'x.x.x.x-y.y.y.y'
 *
 * J. Adams <jna@twitter.com>
 * Twitter, Inc.
 *
 * TODO
 *
 * - Design way to list all ratelimits in a handler page
 * - make INC/DEC work for ratelimits
 * - Response based error handling by IP, using generic handler.
 *    MBResponseLimit 200 100s (s,m,h, etc.)   ---> rate_200_127.0.0.1:cnt:time
 * - Whitelists, and dealing with keys dropping out of memcache.
 * - Make sure confs work per-vhost
 *
 * FUTURE
 * - Support for IPv6
 *
 * (untested) automatic reconnect to dead memcache server
 *
 */

/*

General operation:

Child init - allocate memory and get memcache server list from
config.

Use the memcache list to pull the ban list.
- Do this by issuing GETs for keys "blockkeyN" through "blockkeyMAXN"
  from memcached, storing into the module specific

Every N requests, flush the blocklist and reload it from the server.

*/

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_connection.h"

#include "apr_strings.h"
#include "apr_tables.h"
#include "memcached.h"

#include <stdio.h>

/* Macro to test for valid IP address in four integers */
#define VALID_IP(IP) ((IP[0]<256) && (IP[1]<256) && (IP[2]<256) && (IP[3]<256))
/* Macro to build 32-bit IP from four integers */
#define BUILD_IP(IP) ((IP[0]<<24) | (IP[1]<<16) | (IP[2]<<8) | IP[3])

/* Configuration defaults */
#define MB_DEFAULT_TIMEOUT      5
#define MB_DEFAULT_MAXBLOCKS    100
/* Maximum number of response codes we'll deal with - increase you need more. */
#define MB_DEFAULT_PREFIX       "mb"
#define MB_DEFAULT_SERVERS      "localhost:11211"
#define MB_DEFAULT_REFRESH      300
#define MB_DEFAULT_EXPIRATION   3600
#define MB_DEFAULT_PORT         11211

typedef struct mb_cfg {
  int enable;      /* if module is on or not */
  int ratelimit_enable;      /* if module is on or not */
  char *prefix;    /* prefix used for the keys */
  char *servers;   /* memcached servers */
  int timeout;     /* memcache server timeout */
  int expiration;  /* default object expiration - only used on set */
  int refresh;     /* blocklist lifetime */
  int maxblocks;   /* maximum number of blocks - should this be a key? */
  apr_hash_t *response_limiter;

} mb_cfg;

typedef struct mb_ratelimiter {
  int response_code; /* HTTP response code */
  int count;         /* max count */
  int seconds;       /* duration of timeframe */
} mb_ratelimiter;

/* module-private memory pool - mutexes go here as this is global. */
static apr_pool_t *mb_private_pool = NULL;
static apr_thread_mutex_t *blocklistlock = NULL;

/* updates to the next two variables should only be by mutex */
static apr_table_t *blocklist_table = NULL;

time_t blocklist_last_refresh;

/* global pointer to the memcache pool */
memcached_st *mb_memcache = NULL;
memcached_server_st *mb_servers = NULL;

module AP_MODULE_DECLARE_DATA memcache_block_module;

/* ------------------------ CIDR routines ------------------------ */

/* Specifies a network. Whether originally in CIDR format (IP/mask) or
   a range of IPs (IP_start-IP_end), spec is converted to a range.  The
   range is min to max (32-bit IPs) inclusive.
*/
struct netspec
{
  unsigned int min;
  unsigned int max;
};

/*
  Convert IP address string to 32-bit integer version
  Returns 0 on failure
*/
unsigned int ip_to_uint(const char* ip)
{
  unsigned int IP[4];     /* 4 octets for IP address */
  if ((sscanf(ip, "%u.%u.%u.%u", &IP[0], &IP[1], &IP[2], &IP[3]) == 4) && VALID_IP(IP))
    return BUILD_IP(IP);
  else
    return 0;
}

/*
  Given string, fills in the struct netspec (must be allocated)
  Accept CIDR IP/mask format or IP_start-IP_end range.
  Returns true (nonzero) on success, false (zero) on failure.
*/
int net_parse(const char* line, struct netspec* spec)
{
  unsigned int IP1[4], IP2[4];
  int maskbits = 32;	/* if using CIDR IP/mask format */

  /* Try parsing IP/mask, CIDR format */
  if (strchr(line, '/') && (sscanf(line, "%u.%u.%u.%u/%d", &IP1[0], &IP1[1], &IP1[2], &IP1[3], &maskbits) == 5)
      && VALID_IP(IP1) && (maskbits >= 1) && (maskbits <= 32))
    {
      spec->min = BUILD_IP(IP1) & (~((1 << (32-maskbits))-1) & 0xFFFFFFFF);
      spec->max = spec->min | (((1 << (32-maskbits))-1) & 0xFFFFFFFF);
      return 1;
    }

  /* Try parsing a range */
  else if (strchr(line, '-') && (sscanf(line, "%u.%u.%u.%u-%u.%u.%u.%u", &IP1[0], &IP1[1], &IP1[2], &IP1[3],
					&IP2[0], &IP2[1], &IP2[2], &IP2[3]) == 8) && VALID_IP(IP1) && VALID_IP(IP2))
    {
      spec->min = BUILD_IP(IP1);
      spec->max = BUILD_IP(IP2);
      if (spec->max >= spec->min)
	return 1;
      else
	return 0;
    }
  /* Try simple IP address */
  else if ((sscanf(line, "%u.%u.%u.%u", &IP1[0], &IP1[1], &IP1[2], &IP1[3]) == 4) && VALID_IP(IP1))
    {
      spec->min = BUILD_IP(IP1);
      spec->max = spec->min;
      return 1;
    }
  return 0;	/* could not parse */
}

/* Compare two netspecs, for sorting. Comparison is done on minimum of range */
int netsort(const void* a, const void* b)
{
  unsigned int c1 = ((struct netspec*)a)->min;
  unsigned int c2 = ((struct netspec*)b)->min;
  if (c1 < c2) return -1;
  if (c1 > c2) return +1;
  return 0;
}

/* Compare two netspecs, for searching. Test if key (only min) is inside range */
int netsearch(const void* a, const void* b)
{
  unsigned int key = ((struct netspec*)a)->min;
  unsigned int min = ((struct netspec*)b)->min;
  unsigned int max = ((struct netspec*)b)->max;
  if (key < min) return -1;
  if (key > max) return +1;
  return 0;
}


/*
 * Locate our server configuration record for the specified server.
 */
static mb_cfg *our_sconfig(const server_rec *s)
{
    return (mb_cfg *) ap_get_module_config(s->module_config, &memcache_block_module);
}

/* rebuild the block list */
static mb_refresh_blocklist(server_rec *s)
{
  mb_cfg *cfg;
  char *result;
  char key[255];
  cfg = our_sconfig(s);
  int bnum;
  memcached_result_st *rv;
  memcached_return mc_error;
  size_t len;
  int entries = 0;
  unsigned int flags;

  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
	       "Blocklist refresh start");
  /* lock mutex */
  apr_thread_mutex_lock(blocklistlock);

  /* microscopic window of oppurtunity here
     bad actors might sneak in when BL is empty
   */

  if (blocklist_table == NULL) {
    /* need to create it */
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
	       "Blocklist create");
    blocklist_table = apr_table_make(mb_private_pool, cfg->maxblocks);
  } else {
    apr_table_clear(blocklist_table);
  }

  /* load blocklist */
  for (bnum=0; bnum < cfg->maxblocks; bnum++) {
    snprintf(key, 254, "%s:b:%d",cfg->prefix,bnum);
    result = memcached_get(mb_memcache, key, strlen(key), &len, &flags, &mc_error);

    if (result != NULL) {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
		   "FOUND: key %s = %s ",key,result);
      apr_table_set(blocklist_table,key,result);
      entries++;
    }

    if (mc_error != MEMCACHED_SUCCESS && mc_error != MEMCACHED_NOTFOUND) {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
		   "Memcache Error: key %s: %s",key, memcached_strerror(mb_memcache,mc_error));
    }
  }

  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
	       "Blocklist refresh complete (%d entries found)",entries);
  blocklist_last_refresh = time(NULL);

  /* unlock mutex */
  apr_thread_mutex_unlock(blocklistlock);
}


/*
 * setup some module-wide cells if they haven't been alloc'd
 */

static void setup_module_cells(void)
{
  /*
   * If we haven't already allocated our module-private pool, do so now.
   */
  if (mb_private_pool == NULL) {
    apr_pool_create(&mb_private_pool, NULL);
  };
}

static void *mb_mkconfig(apr_pool_t *p)
{
  mb_cfg *cfg;

  /*
   * As with the mb_create_dir_config() reoutine, we allocate and fill
   * in an empty record.   */
  cfg = (mb_cfg *) apr_pcalloc(p, sizeof(mb_cfg));

  /* init new server config here */
  cfg->enable = 1;
  cfg->prefix = apr_pstrcat(p,MB_DEFAULT_PREFIX,NULL);
  cfg->servers = apr_pstrcat(p,MB_DEFAULT_SERVERS,NULL);

  cfg->expiration = MB_DEFAULT_EXPIRATION;
  cfg->maxblocks  = MB_DEFAULT_MAXBLOCKS;
  cfg->timeout    = MB_DEFAULT_TIMEOUT;
  cfg->refresh    = MB_DEFAULT_REFRESH;

  cfg->ratelimit_enable = 1;
  cfg->response_limiter = apr_hash_make(p);
  return (void *) cfg;
}

/*
 * create the per server configuration
 */

static void *mb_create_server_config(apr_pool_t *p, server_rec *s)
{
  return mb_mkconfig(p);
}

static void *mb_create_dir_config(apr_pool_t *p, char *dir) {
  return mb_mkconfig(p);
}

static void *mb_merge_server_config(apr_pool_t *p, void *server1_conf,
                                         void *server2_conf)
{
  mb_cfg *merged_config = (mb_cfg *) apr_pcalloc(p, sizeof(mb_cfg));
  mb_cfg *s1conf = (mb_cfg *) server1_conf;
  mb_cfg *s2conf = (mb_cfg *) server2_conf;

  merged_config->enable = s2conf->enable;
  merged_config->prefix = apr_pstrdup(p, s2conf->prefix);
  merged_config->servers = apr_pstrdup(p, s2conf->servers);
  merged_config->expiration = s2conf->expiration;
  merged_config->maxblocks = s2conf->maxblocks;
  merged_config->timeout = s2conf->timeout;
  merged_config->refresh = s2conf->refresh;

  merged_config->ratelimit_enable = s2conf->ratelimit_enable;

  if (s2conf->response_limiter != NULL) {
    merged_config->response_limiter = apr_hash_copy(p, s2conf->response_limiter);
  }
}

static apr_status_t mb_child_exit(void *data)
{
  char *note;
  server_rec *s = data;
  char *sname = s->server_hostname;

  /* TODO: clean up any alloc'd resources and die */
  /* TODO: free memcache resources */
  return APR_SUCCESS;
}

static int mb_init(apr_pool_t * p, apr_pool_t * plog,
		    apr_pool_t * ptemp, server_rec * s)
{
  char *sname = s->server_hostname;
  char *svr,*tok;
  char *tok_cntx;

  apr_status_t rv;
  mb_cfg *cfg;
  memcached_return rc;

  /*
   * Set up any module cells that ought to be initialised.
   */
  setup_module_cells();
  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "child init called.");
  apr_pool_cleanup_register(p, s, mb_child_exit, mb_child_exit);

  mb_memcache = memcached_create(NULL);
  /* parse the server list and setup memcache connections */
  cfg = our_sconfig(s);

  if (mb_servers == NULL) {
    mb_servers = memcached_servers_parse(cfg->servers);
    rc = memcached_server_push(mb_memcache,mb_servers);
    memcached_server_list_free(mb_servers);
  }

  /* create mutex */
  apr_thread_mutex_create(&blocklistlock,APR_THREAD_MUTEX_UNNESTED,mb_private_pool);

  /* finally, refresh the blocklist */
  mb_refresh_blocklist(s);

}

/* callback used when we walk the array */
int mb_check_ip(void *rec, const char *key, const char *value)
{
  struct netspec their_ip;
  struct netspec test_ip;
  int o_rv,t_rv;

  /* absolute match? */
  if (strcmp(value,rec) == 0) {
    return FALSE;
  }

  /* try parsing */
  t_rv = net_parse(rec,&their_ip);
  o_rv = net_parse(value,&test_ip);

  if ((o_rv == 1) && (t_rv == 1)) {
    if (netsearch(&their_ip,&test_ip) == 0) {
      /* hit */
      return FALSE;
    }
  }
  
  return TRUE;
}

static int mb_access_checker(request_rec *r)
{
  mb_cfg *cfg;
  char *result;
  char key[255];
  uint32_t flags; 
  size_t len;
  mb_cfg *sconf;
  memcached_return mc_error;

  sconf = our_sconfig(r->server);

  /* before we perform our lookup, is it time to refresh the table? */
  if ((time(NULL) - blocklist_last_refresh) > cfg->refresh ) {
    mb_refresh_blocklist(r->server);
  }
  
  /* do we have an entry in the lockout memcache */
  snprintf(key, 254, "%s:d:%s",sconf->prefix,r->connection->remote_ip);
  result = memcached_get(mb_memcache, key, strlen(key), &len, &flags, &mc_error);

  if (result) { 
    if (*result == '1') {
      return HTTP_FORBIDDEN;
    }
  }


  /* do we have an entry in the blacklist? */
  if (apr_table_do(mb_check_ip, r->connection->remote_ip, blocklist_table,NULL) == FALSE) {
    return HTTP_FORBIDDEN;
  } else {
   return DECLINED;
  }
}

static int mb_logger(request_rec *r)
{
  mb_cfg *sconf;
  mb_ratelimiter *rl = NULL;
  uint64_t count;
  uint32_t flags;
  size_t len;
  char *result;
  char key[255];
  char lastkey[255];
  char time_s[16];
  char *one_s = "1";
  memcached_result_st rv;
  memcached_return mc_error;

  char *status = apr_itoa(r->pool, r->status);
  sconf = our_sconfig(r->server);

  /* Are we tracking this response? */
  if (r->status > 0) {
    rl = apr_hash_get(sconf->response_limiter,status,APR_HASH_KEY_STRING);
    if (rl != NULL) {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
		   "Found limiter for response %d, count %d, time %d",rl->response_code,rl->count,rl->seconds);

      /* update memcache */
      snprintf(key, 254, "%s:c:%s:%d",sconf->prefix,r->connection->remote_ip,rl->response_code);
      snprintf(lastkey, 254, "%s:l:%s:%d",sconf->prefix,r->connection->remote_ip,rl->response_code);
      snprintf(time_s, 15, "%d",time(NULL));

      mc_error = memcached_increment(mb_memcache, key, strlen(key), 1, &count);

      if (mc_error == MEMCACHED_NOTFOUND) { 
	mc_error = memcached_set(mb_memcache, key, strlen(key), one_s, strlen(one_s), 0 , 0);
	count = 1;
	/* this is the first time for this code, store time in last_access field */
	mc_error = memcached_set(mb_memcache, lastkey, strlen(lastkey), time_s, strlen(time_s), 0 , 0);
      } else {
	/* TODO: it was found. if the record is too old, clear the counter and skip the next step */
      }

      if (mc_error != MEMCACHED_SUCCESS && mc_error != MEMCACHED_NOTFOUND) {
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
		     "Memcache Error: key %s: %s",key, memcached_strerror(mb_memcache,mc_error));
	return DECLINED;
      } else {
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
		     "memcache_block: key %s count=%d",key, count);
      }

      /* check limits */
      if (count > rl->count) {
	/* insert block */
	snprintf(key, 254, "%s:d:%s",sconf->prefix,r->connection->remote_ip); 
	mc_error = memcached_set(mb_memcache, key, strlen(key), one_s, strlen(one_s), sconf->expiration , 0);

	if (mc_error != MEMCACHED_SUCCESS) { 
	  ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
		       "Memcache Error (in lockout): key %s: %s",key, memcached_strerror(mb_memcache,mc_error));
	  
	} else {
	  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
		       "memcache_block: lockout ip %s, %d %ds in %d interval",r->connection->remote_ip, count, r->status, rl->seconds);
	  /* TODO: remove counter for this resp code. */
	}

	return HTTP_FORBIDDEN;
      }

    }
  }

  return DECLINED;
}

static void mb_register_hooks(apr_pool_t *p)
{
  /* set all of the processing hooks for memcache IP blocking */
  ap_hook_post_config(mb_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_access_checker(mb_access_checker, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_log_transaction(mb_logger, NULL, NULL, APR_HOOK_MIDDLE);
}

/*
 * List of directives specific to our module.
 */

/* handle options here */
static const char *set_enable(cmd_parms * cmd, void *dconf, int flag)
{
  mb_cfg *sconf;

  sconf = (mb_cfg *) ap_get_module_config(cmd->server->module_config, &memcache_block_module);
  sconf->enable = (flag ? 1 : 0);
  return NULL;
}

static const char *set_ratelimit_enable(cmd_parms * cmd, void *dconf, int flag)
{
  mb_cfg *sconf;

  sconf = (mb_cfg *) ap_get_module_config(cmd->server->module_config, &memcache_block_module);
  sconf->ratelimit_enable = (flag ? 1 : 0);
  return NULL;
}

static const char *set_servers(cmd_parms * cmd, void *dconf, const char *s)
{
  mb_cfg *sconf;
  sconf = (mb_cfg *) ap_get_module_config(cmd->server->module_config, &memcache_block_module);
  sconf->servers = (char *)s;
  return NULL;
}

static const char *set_prefix(cmd_parms * cmd, void *dconf, const char *s)
{
  mb_cfg *sconf;
  sconf = (mb_cfg *) ap_get_module_config(cmd->server->module_config, &memcache_block_module);
  sconf->prefix = (char *)s;
  return NULL;
}

static const char *set_timeout(cmd_parms * cmd, void *dconf, const char *s)
{
  mb_cfg *sconf;
  sconf = (mb_cfg *) ap_get_module_config(cmd->server->module_config, &memcache_block_module);
  sconf->timeout = atoi(s);
  return NULL;
}

static const char *set_expiration(cmd_parms * cmd, void *dconf, const char *s)
{
  mb_cfg *sconf;
  sconf = (mb_cfg *) ap_get_module_config(cmd->server->module_config, &memcache_block_module);
  sconf->expiration = atoi(s);
  return NULL;
}

static const char *set_refresh(cmd_parms * cmd, void *dconf, const char *s)
{
  mb_cfg *sconf;
  sconf = (mb_cfg *) ap_get_module_config(cmd->server->module_config, &memcache_block_module);
  sconf->refresh = atoi(s);
  return NULL;
}

static const char *set_maxblocks(cmd_parms * cmd, void *dconf, const char *s)
{
  mb_cfg *sconf;
  sconf = (mb_cfg *) ap_get_module_config(cmd->server->module_config, &memcache_block_module);
  sconf->maxblocks = atoi(s);
  return NULL;
}


static const char *set_response_limiter(cmd_parms *cmd, void *dconf, const char *s1, const char *s2, const char *s3)
{
  mb_cfg *sconf;
  sconf = (mb_cfg *) ap_get_module_config(cmd->server->module_config, &memcache_block_module);
  server_rec *s = cmd->server;
  mb_ratelimiter *rl;

  if (mb_private_pool == NULL) {
    apr_pool_create(&mb_private_pool, NULL);
  };

  /* add the desired handler to our list... */
  if ((atoi(s1) > 0) && (atoi(s2) > 0) && (atoi(s3) > 0)) {
    rl = apr_palloc(mb_private_pool,sizeof(mb_ratelimiter));

   rl->response_code = atoi(s1);
   rl->count = atoi(s2);
   rl->seconds = atoi(s3);
   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
		"Add rate limiter, HTTP Response code %d, %d req in %d seconds",rl->response_code,rl->count,rl->seconds);
   const char *k1 = apr_pstrdup(mb_private_pool,s1);

   apr_hash_set(sconf->response_limiter, k1, APR_HASH_KEY_STRING, rl);
   return NULL;

  } else {
    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
		 "MemcacheBlock: %s: (%s line %d) cannot parse. Usage: MBResponseLimit http_numeric_response count duration", cmd->cmd->name, cmd->directive->filename,cmd->directive->line_num);
    return NULL;
  }
}


static const command_rec mb_cmds[] =
{
  /* string options */
  AP_INIT_FLAG("MBEnable", set_enable, NULL, RSRC_CONF,
               "On or Off, controls if this module is enabled or not (default on)"),

  AP_INIT_TAKE1("MBServers", set_servers, NULL, RSRC_CONF,
		"List of memcached servers to use (in server:port format, seperated by commas)"),

  AP_INIT_TAKE1("MBPrefix", set_prefix, NULL, RSRC_CONF,
                "Memcache Key Prefix - prepended to each block key (prefixN)"),

  /* these all take ints */
  AP_INIT_TAKE1("MBTimeout", set_timeout, NULL, RSRC_CONF,
                "Memcache Server Timeout"),

  AP_INIT_TAKE1("MBExpiration", set_expiration, NULL, RSRC_CONF,
                "Expiration time placed on items which are placed into memcached"),

  AP_INIT_TAKE1("MBTableRefresh", set_refresh, NULL, RSRC_CONF,
                "How long (seconds) before we consider our local copy of the block list to be stale (Triggers refresh on next request)"),

  AP_INIT_TAKE1("MBMaxBlocks",  set_maxblocks, NULL, RSRC_CONF,
                "Maximum number of blocks the system will check for"),


  AP_INIT_TAKE3("MBResponseLimit", set_response_limiter, NULL, RSRC_CONF,
		"Rate limit by response code, in N seconds"),

  AP_INIT_FLAG("MBRateLimit", set_ratelimit_enable, NULL, RSRC_CONF,
               "On or Off, controls if this module is enabled or not (default On)"),


  {NULL}
};


/*
 * Module definition for configuration.  If a particular callback is not
 * needed, replace its routine name below with the word NULL.
 */
module AP_MODULE_DECLARE_DATA memcache_block_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,     /* dir config merger */
    mb_create_server_config, /* server config creator */
    NULL,     /* server config merger */
    mb_cmds,            /* command table */
    mb_register_hooks,  /* set up other request processing hooks */
};


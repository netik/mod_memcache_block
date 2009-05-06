/*
  mod_telemetry - collect timings and status statistics for requests

  John Adams <jna@retina.net>
  Retina Communications
  http://www.retina.net/tech
  
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

  Please see the INSTALL and README files for details on how to build
  this module.

  THIS MODULE REQUIRES THAT MOD_SCOREBOARD BE ENABLED. 

  Contains code derived from mod_bw (Ivan Barrera A.)
  http://bwmod.sourceforge.net

  ...and mod_alias + mod_status (Apache Group)
  http://www.apache.org

*/

#define VERSION "1.0"

/* uncomment to enable detailed debugging */
#define DEBUG 1

/*
 * Include the core server components.
 */
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "apr_tables.h"
#include "apr_pools.h"
#include "apr_time.h"
#include "apr_hash.h"

#include "apr_atomic.h"
#include "apr_shm.h"
#include "time.h"

#include "scoreboard.h"

/* Configuration ---------------------------------------------------------------------------- */
#define TM_MAX_URIS 100000   /* max URIs tracked */
#define TM_MAX_IPS  100000   /* max IPs tracked */

#define TM_MAX_DISPLAY_IP      250 /* max number of IPs to display in tracking screen */

/* 43,200,000 mS = 12 hours */
#define TM_EVICTION_THRESHOLD  43200000 /* after this many msec, data is old and should be evicted */


/* scripts that take longer than these many microseconds = slow. */
#define SLOW_THRESHOLD1     (apr_time_t)250
#define SLOW_THRESHOLD5     (apr_time_t)1000
#define SLOW_THRESHOLD10    (apr_time_t)5000

/* TODO: This should probably be moved into a configuration directive */
#define TM_CODES_TRACKED 11
static const int telemetry_tracked_status[] = 
  {200,301,302,304,400,401,403,404,500,502,503};

/* conditional defines here */
#ifndef DEFAULT_TIME_FORMAT
#define DEFAULT_TIME_FORMAT "%A, %d-%b-%Y %H:%M:%S %Z"
#endif

#define TELEM_MAGIC_TYPE "application/x-httpd-telem"

#define MOD_COPYRIGHT_STRING "<HR><I>mod_telemetry -- John Adams &lt;jna@retina.net&gt; -- <a href=\"http://code.google.com/p/modtelemetry/\">http://code.google.com/p/modtelemetry/</a></i>"

#define TELEM_DISABLED             1<<0
#define TELEM_ENABLED              1<<1

/* NULL for Anonymous shared memory segment. not implemented on all
   systems */

#define TM_SHM_FILENAME            NULL

/* options */ 
#define OPT_END       -1
#define OPT_RESET     0
#define OPT_SRT_URI   1
#define OPT_SRT_HITS  2
#define OPT_SRT_LASTDELTA  3
#define OPT_SRT_MIN   4
#define OPT_SRT_MAX   5
#define OPT_SRT_AVG   6
#define OPT_SRT_SLOW  7
#define OPT_SRT_LASTACC 8

/* Compatibility with regex on apache less than 2.1 */
#if !AP_MODULE_MAGIC_AT_LEAST(20050127,0)
    typedef regex_t ap_regex_t;
    #define AP_REG_EXTENDED REG_EXTENDED
    #define AP_REG_ICASE REG_ICASE
#endif

/* Compatibility for APR < 1 */
#if ( defined(APR_MAJOR_VERSION) && (APR_MAJOR_VERSION < 1) )
    #define apr_atomic_inc32 apr_atomic_inc
    #define apr_atomic_dec32 apr_atomic_dec
    #define apr_atomic_add32 apr_atomic_add
    #define apr_atomic_cas32 apr_atomic_cas
    #define apr_atomic_set32 apr_atomic_set
#endif

/* regexps - making struct here so I have room to grow */
typedef struct { 
  ap_regex_t *regexp; 
} tm_match_entry;

/* options structure */
struct telem_opt
{
    int id;
    const char *form_data_str;
    const char *hdr_out_str;
};

/* sorting commands */
static const struct telem_opt telemetry_options[] =     /* see #defines above */
{
    {OPT_RESET, "reset", "Reset"},
    {OPT_SRT_URI, "uri", ""},
    {OPT_SRT_HITS, "hits", ""},
    {OPT_SRT_LASTDELTA, "last", ""},
    {OPT_SRT_MIN, "min", ""},
    {OPT_SRT_MAX, "max", ""},
    {OPT_SRT_AVG, "avg", ""},
    {OPT_SRT_SLOW, "slow", ""},
    {OPT_SRT_LASTACC, "lastacc", ""},
    {OPT_END, NULL, NULL}
};

/* this global struct holds additional scoreboard information */
typedef struct telem_global_s 
{
  apr_uint32_t total_hits;
  apr_time_t   lastreset;
} telem_global;

/* this struct stores data about each unique URI */
typedef struct telemetry_s
{
  char uri[255];
  
  /* how many times it's violated each slow threshold */
  apr_uint32_t slowsone;
  apr_uint32_t slowsfive;
  apr_uint32_t slowsten;
  
  /* times */
  apr_time_t min;
  apr_time_t max;
  apr_time_t avg;
  apr_time_t last;
  apr_time_t lastdelta;

  long resultcode[TM_CODES_TRACKED];

  /* number of hits */
  apr_uint32_t hits;
  
  /* lock for this structure */
  volatile apr_uint32_t lock;
  
} telem_data;

typedef struct telemetry_track_ip_s
{
  char ip[15]; 
  apr_time_t last;
  long hits;
} telem_trackip;

typedef struct telemetry_aggregate_s
{
  apr_uint32_t hits;
  long resultcodetotals[TM_CODES_TRACKED];
  telem_trackip trackedip[TM_MAX_IPS];

} telem_aggregate_data;

/* per server options configuration */
typedef struct
{
  int state;       /* enabled or disabled */
  int imgfilter;   /* enabled or disabled */
  int onlyvalid;   /* enabled or disabled */
  int jscssfilter; /* enabled or disabled */
  int iptrack;     /* enabled or disabled */

  /* TelemetryMatch regexps */
  apr_array_header_t *matchregexps;

} telemetry_server_config;

/* Globals ---------------------------------------------------------------------------------- */

telemetry_server_config *globalconf;        /* keep a pointer around to the configuration so we have it */
apr_shm_t *shm;
telem_aggregate_data *tmaggbase;
telem_data *tmbase;

/* default sort */
int sortby = OPT_SRT_MAX;

/* max hash sizes */
static int sid = TM_MAX_URIS;

/* Module start ----------------------------------------------------------------------------- */

module AP_MODULE_DECLARE_DATA telemetry_module;

/* Utility Functions */
unsigned long djbhash(char *str)
{
    unsigned long hash = 5381;
    unsigned char c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c;        /* hash * 33 + c */

    return hash;
}

static char *show_apr_time(apr_time_t tsecs)
{
  /* show an apr_time_t */ 
  int hrs, mins, secs;
  static char mystr[50];
  tsecs /= 1000;

  secs = (int) (tsecs % 60);
  tsecs /= 60;
  mins = (int) (tsecs % 60);
  tsecs /= 60;
  hrs = (int) (tsecs % 24);

  sprintf(mystr, "%02d:%02d:%02d.%02d",hrs,mins,secs);

  return mystr;
}

static void show_time(request_rec * r, apr_interval_time_t tsecs)
{
    int days, hrs, mins, secs;

    secs = (int) (tsecs % 60);
    tsecs /= 60;
    mins = (int) (tsecs % 60);
    tsecs /= 60;
    hrs = (int) (tsecs % 24);
    days = (int) (tsecs / 24);

    if (days)
        ap_rprintf(r, " %d day%s", days, days == 1 ? "" : "s");

    if (hrs)
        ap_rprintf(r, " %d hour%s", hrs, hrs == 1 ? "" : "s");

    if (mins)
        ap_rprintf(r, " %d minute%s", mins, mins == 1 ? "" : "s");

    if (secs)
        ap_rprintf(r, " %d second%s", secs, secs == 1 ? "" : "s");
}

char *stristr(const char *String, const char *Pattern)
{
    char *pptr, *sptr, *start;
    uint slen, plen;

    for (start = (char *) String,
         pptr = (char *) Pattern,
         slen = strlen(String), plen = strlen(Pattern);
         /* while string length not shorter than pattern length */
         slen >= plen; start++, slen--) {
        /* find start of pattern in string */
        while (toupper(*start) != toupper(*Pattern)) {
            start++;
            slen--;

            /* if pattern longer than string */

            if (slen < plen)
                return (NULL);
        }

        sptr = start;
        pptr = (char *) Pattern;

        while (toupper(*sptr) == toupper(*pptr)) {
            sptr++;
            pptr++;

            /* if end of pattern then pattern was found */

            if ('\0' == *pptr)
                return (start);
        }
    }
    return (NULL);
}

static const char *add_match_regex(cmd_parms *cmd, void *dummy, const char *f)
{
  /* taken from mod_alias.c */
  server_rec *s = cmd->server;

  telemetry_server_config *conf =
    (telemetry_server_config *) ap_get_module_config(s->module_config,
						     &telemetry_module);
  
  tm_match_entry *new = apr_array_push(conf->matchregexps);

  new->regexp = ap_pregcomp(cmd->pool, f, AP_REG_EXTENDED);

  if (new->regexp == NULL)
    return "Regular expression could not be compiled.";

  return (NULL);
}


static int tm_track_ip(char *ip)
{
  unsigned long loc;
  loc = djbhash(ip) % TM_MAX_IPS;
  apr_time_t now;

  now = (apr_time_t) apr_time_now();
  
  /* old entry and match, or new stuff? */
  if ((strcmp(tmaggbase->trackedip[loc].ip, ip) == 0) ||
      (strcmp(tmaggbase->trackedip[loc].ip, "") == 0)) {
    strcpy(tmaggbase->trackedip[loc].ip, ip);
    apr_atomic_inc32(&tmaggbase->trackedip[loc].hits);
    fprintf(stderr,"track IP %s / %d hits @ %d\n", ip, tmaggbase->trackedip[loc].hits,loc);
    tmaggbase->trackedip[loc].last = now;
    /* release lock */
  } else {
    /* slot is taken by another member. Can we evict? */
    apr_time_t delta = (apr_time_t) (now - tmaggbase->trackedip[loc].last);
    if (apr_time_as_msec(delta) > TM_EVICTION_THRESHOLD) {
      /* evict the member. */
      fprintf(stderr,"HASH EVICTION: %s for IP %s / %d hits @ %d\n", tmaggbase->trackedip[loc].ip,ip, tmaggbase->trackedip[loc].hits,loc);
      strcpy(tmaggbase->trackedip[loc].ip, ip);
      apr_atomic_set32(&tmaggbase->trackedip[loc].hits,1);
      tmaggbase->trackedip[loc].last = now;
    } else {
      fprintf(stderr,"mod_telemetry: Cannot add IP and cannot evict existing member. Hash collision. Increase TM_MAX_IPS.");      
    }
  }
}


/* modtelemetry_log
 * 
 * log the request into SHM, based on configuration criteria. Final module method.
 */
static int modtelemetry_log(request_rec * r)
{
    struct timeval start;
    const char *timestr;
    apr_time_t t1, t2;
    ap_regmatch_t regm[AP_MAX_REG_MATCH];
    int c,i;
    int found;
    unsigned long loc;
    
    /* are we enabled? */
    if (globalconf->state != TELEM_ENABLED) { 
      return DECLINED;
    }

    if (globalconf->onlyvalid == TELEM_ENABLED) { 
      /* track only valid */
      if (!ap_is_HTTP_SUCCESS(r->status)) {
	return DECLINED;
      }
    }

    /* record IP */
    if (globalconf->iptrack == TELEM_ENABLED) { 
      tm_track_ip(r->connection->remote_ip); 
    }
    
    if (globalconf->imgfilter == TELEM_ENABLED) { 
      /* filter out images */
      if ((stristr(r->uri, ".jpg") != NULL) ||
	  (stristr(r->uri, ".jpeg") != NULL) ||
	  (stristr(r->uri, ".png") != NULL) ||
	  (stristr(r->uri, ".gif") != NULL)) {
        return DECLINED;
      }
    }

    if (globalconf->jscssfilter == TELEM_ENABLED) { 
      /* filter out css and js */
      if ( (stristr(r->uri, ".js") != NULL)  || 
		   (stristr(r->uri, ".css") != NULL) ) 
		{
        	return DECLINED;
      	}
    }

    /* at this point, we have a match unless regexp tells us otherwise */
    found = TRUE;

    /* process regexps (TelemetryMatch) */
    tm_match_entry *entries = (tm_match_entry *) globalconf->matchregexps->elts;
    if (globalconf->matchregexps->nelts > 0) { 
      found = FALSE; 
      /* any match is a good match. */
      for (i = 0; i < globalconf->matchregexps->nelts; ++i) {      
        tm_match_entry *p = &entries[i];
	if (!ap_regexec(p->regexp, r->uri, AP_MAX_REG_MATCH, regm, 0)) { 
	  found = TRUE;
	}
      }
    }

    /* did we fail? */
    if (found == FALSE) { 
      return DECLINED;
    }

    /* establish lock here -- critical section */
    timestr = apr_table_get(r->notes, "tm_start");

    if (timestr) {
      /* I don't know why strtoll works here and apr_atoi64 does not, but I am using strtoll.. */
      t1 = (apr_time_t) strtoll(timestr, NULL, 10);
      t2 = (apr_time_t) apr_time_now();
    } else { 
      /* we didn't find an original matching entry.
       * maybe the request notes entry got corrupted? punt.
       */
      return DECLINED;
    }
    
    apr_time_t delta = (apr_time_t) (t2 - t1);
    
    /* store data to SHM */
    /* FUTURE: handle hash collisions more sanely - expiry? */
    loc = djbhash(r->uri) % sid;
#ifdef DEBUG
    fprintf(stderr,"my loc = %d for %s http code %d\n", loc , r->uri,r->status);
#endif
    /* old entry and match, or new stuff? */
    if ((strcmp(tmbase[loc].uri, r->uri) == 0) ||
	(strcmp(tmbase[loc].uri, "") == 0)) {
      
      /* increment appropriate status code if we are tracking it */
      for (c=0; c < TM_CODES_TRACKED; c++)   { 
	if (telemetry_tracked_status[c] == r->status) {
	  apr_atomic_inc32(&tmaggbase[0].resultcodetotals[c]);
	  apr_atomic_inc32(&tmbase[loc].resultcode[c]);
	}
      }
	
	strcpy(tmbase[loc].uri, r->uri);
	tmbase[loc].last = t1;
	
	/* is this a slow script? */
	if (apr_time_as_msec(delta) > SLOW_THRESHOLD1) {
	  apr_atomic_inc32(&(tmbase[loc].slowsone));
	}
	if (apr_time_as_msec(delta) > SLOW_THRESHOLD5) {
	  apr_atomic_inc32(&(tmbase[loc].slowsfive));
	}
	if (apr_time_as_msec(delta) > SLOW_THRESHOLD10) {
	  apr_atomic_inc32(&(tmbase[loc].slowsten));
	}
	
	apr_atomic_set32(&(tmbase[loc].lastdelta),delta);

	apr_atomic_inc32(&(tmaggbase[0]).hits);
	apr_atomic_inc32(&(tmbase[loc]).hits);

	/* FIXME: Convert all reads to atomic reads */
	
	/* moving avg, is this right? */
	if (tmbase[loc].avg == 0) {
	  apr_atomic_set32(&(tmbase[loc].avg),delta);
	} else {
	  apr_atomic_set32(&(tmbase[loc].avg), (tmbase[loc].avg + delta) / 2);
	}
	
	if (delta > tmbase[loc].max) {
	  apr_atomic_set32(&(tmbase[loc].max),delta);
	};
	
	if ((delta < tmbase[loc].min) || (tmbase[loc].min == 0)) {
	  apr_atomic_set32(&(tmbase[loc].min),delta);
	};

#ifdef DEBUG
    fprintf(stderr, "mod_telemetry (TRACK REQ): %s start=%" APR_TIME_T_FMT " end=%" APR_TIME_T_FMT
            " min=%" APR_TIME_T_FMT
            " max=%" APR_TIME_T_FMT
            " avg=%" APR_TIME_T_FMT
            "\n", r->uri, t1, t2, tmbase[loc].min, tmbase[loc].max,
            tmbase[loc].avg);
#endif

    fflush(stderr);
        } else {
          fprintf(stderr,"mod_telemetry : Warning: hash collision. (r->uri != stored uri) increase size of hash. Timing data for this URI has not been collected.");
        }
        /* if existing or empty uri */
    return DECLINED;
}

static int reset_counters(apr_pool_t * p, server_rec * s)
{
    /* zero out all counters in shared memory */
    apr_status_t status;
    apr_size_t retsize;
    telem_data *tmstat;
    int t;

    retsize = apr_shm_size_get(shm);

    /* wipe shm */
    memset(tmaggbase, 0, retsize);

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                 "mod_telemetry : Shared Memory Allocated %d bytes (each URI = %d bytes)",
                 (int) retsize, (int) sizeof(telem_data));

    if (retsize < ( sizeof(telem_aggregate_data) + (sizeof(telem_data) * sid))) { 
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                     "mod_telemetry : Requested SHM size wasn't honored by the kernel. Increase shmmmax?");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                 "mod_telemetry : Counters Reset. Current options are Enabled=%s ImgFilter=%s jscssfilter=%s Onlyvalid=%s\n",
		 (globalconf->state == TELEM_ENABLED ? "On": "Off"),
		 (globalconf->imgfilter == TELEM_ENABLED ? "On": "Off"),
		 (globalconf->jscssfilter == TELEM_ENABLED ? "On": "Off"),
		 (globalconf->onlyvalid == TELEM_ENABLED ? "On": "Off"));

}

/* sort functions */
static int cmp_maxtime(const void *p1, const void *p2)
{
    int i = *((int *) p1);
    int j = *((int *) p2);

    /* compare tmbase times */
    if (tmbase[i].max < tmbase[j].max)
        return (1);
    if (tmbase[i].max > tmbase[j].max)
        return (-1);

    return (0);
}


static int cmp_mintime(const void *p1, const void *p2)
{
    int i = *((int *) p1);
    int j = *((int *) p2);

    /* compare tmbase times */
    if (tmbase[i].min < tmbase[j].min)
        return (1);
    if (tmbase[i].min > tmbase[j].min)
        return (-1);

    return (0);
}

static int cmp_hits(const void *p1, const void *p2)
{
    int i = *((int *) p1);
    int j = *((int *) p2);

    /* compare tmbase times */
    if (tmbase[i].hits < tmbase[j].hits)
        return (1);
    if (tmbase[i].hits > tmbase[j].hits)
        return (-1);

    return (0);
}

static int cmp_lastdelta(const void *p1, const void *p2)
{
    int i = *((int *) p1);
    int j = *((int *) p2);

    /* compare tmbase times */
    if (tmbase[i].lastdelta < tmbase[j].lastdelta)
        return (1);
    if (tmbase[i].lastdelta > tmbase[j].lastdelta)
        return (-1);

    return (0);
}

static int cmp_lastacc(const void *p1, const void *p2)
{
    int i = *((int *) p1);
    int j = *((int *) p2);

    /* compare tmbase times */
    if (tmbase[i].last < tmbase[j].last)
        return (1);
    if (tmbase[i].last > tmbase[j].last)
        return (-1);

    return (0);
}

static int cmp_avg(const void *p1, const void *p2)
{
    int i = *((int *) p1);
    int j = *((int *) p2);

    /* compare tmbase times */
    if (tmbase[i].avg < tmbase[j].avg)
        return (1);
    if (tmbase[i].avg > tmbase[j].avg)
        return (-1);

    return (0);
}

static int cmp_slow(const void *p1, const void *p2)
{
    int i = *((int *) p1);
    int j = *((int *) p2);

    /* compare tmbase times */
    if (tmbase[i].slowsone < tmbase[j].slowsone)
        return (1);
    if (tmbase[i].slowsone > tmbase[j].slowsone)
        return (-1);

    return (0);
}

static int cmp_ip_hits(const void *p1, const void *p2)
{
    int i = *((int *) p1);
    int j = *((int *) p2);

    /* compare tmbase times */
    if (tmaggbase->trackedip[i].hits < tmaggbase->trackedip[j].hits)
        return (1);
    if (tmaggbase->trackedip[i].hits > tmaggbase->trackedip[j].hits)
        return (-1);

    return (0);
}

static int tm_report_ip(request_rec * r)
{
  int index[TM_MAX_IPS];
  int x;
  int totalrec = 0;
  telem_trackip *trackip;

  /* build index */
  trackip = tmaggbase->trackedip;

  for (x = 0; x < TM_MAX_IPS; x++) {
    if (trackip[x].last > 0) {
      index[totalrec++] = x;
    }
  }

  /* sort the index */
  qsort((void*)index, totalrec, sizeof(int), cmp_ip_hits);
  
  /* Dump the IP Report */
  ap_set_content_type(r, "text/html");
  ap_rputs(DOCTYPE_HTML_3_2
	   "<html>\n"
	   "<head>\n"
	   "<meta http-equiv=\"Pragma\" content=\"no-cache\">\n"
	   "<title>mod_telemetry : IP report</title>\n"
	   "</head>\n"
	   "<body>\n							\
<style type=\"text/css\">						\
body, td, p, div, small, big{						\
font-family: Arial, Helvetica, sans-serif \
}					  \
</style> ", r);
  
  /* header */
  ap_rputs("<h1>mod_telemetry - Top IP hits</h1><P></P>\n",r);
  ap_rputs("<TABLE border=1>\n",r);
  ap_rputs("<TR><TH>IP</TH><TH>Hits</TH><TH>Last Access</TH></TR>\n",r);

  /* body */
   /* TODO: DNS LOOKUPS */
  for (x = 0; (x != totalrec && x < TM_MAX_DISPLAY_IP); x++)  {
    char last_s[APR_CTIME_LEN];
    apr_ctime(last_s, tmaggbase->trackedip[index[x]].last);

    ap_rputs((char *) 
	     apr_psprintf(r->pool,
			  "<TR><TD ALIGN=LEFT>"
			  "<a href=\"http://samspade.org/whois/%s\">%s</a>"
			  "</TD><TD ALIGN=RIGHT>%d</TD><TD>%s</TD></TR>\n",
			  tmaggbase->trackedip[index[x]].ip,
			  tmaggbase->trackedip[index[x]].ip,
			  tmaggbase->trackedip[index[x]].hits,
			  last_s),r);
  }

  ap_rputs("</table><P>" MOD_COPYRIGHT_STRING "</P></body></html>\n", r);
  return OK;
  
}

static int tm_report_detail(request_rec * r)
{
  /* Dump the URI Report */
  int t,ct;
  
  /* make an index of everything in memory */
  int index[TM_MAX_URIS];
  int indices = 0;
  int x;
  int totalrec = 0;
  apr_time_t nowtime;
  apr_interval_time_t up_time;
  
  nowtime = apr_time_now();
  
  for (x = 0; x < sid; x++) {
    if (tmbase[x].last > 0) {
      index[totalrec++] = x;
    }
  }
  
  /* shuffle the index based on sort criteria - default is by max time */
  switch (sortby) {
  case OPT_SRT_LASTDELTA:
    qsort((void *) index, totalrec, sizeof(int), cmp_lastdelta);
        break;
  case OPT_SRT_LASTACC:
    qsort((void *) index, totalrec, sizeof(int), cmp_lastacc);
    break;
  case OPT_SRT_HITS:
    qsort((void *) index, totalrec, sizeof(int), cmp_hits);
    break;
  case OPT_SRT_AVG:
    qsort((void *) index, totalrec, sizeof(int), cmp_avg);
    break;
  case OPT_SRT_SLOW:
    qsort((void *) index, totalrec, sizeof(int), cmp_slow);
    break;
  case OPT_SRT_MIN:
    qsort((void *) index, totalrec, sizeof(int), cmp_mintime);
    break;
  default:                   /* OPT_SRT_MAX */
    qsort((void *) index, totalrec, sizeof(int), cmp_maxtime);
    break;
    }
  
    /* display the page */

    ap_set_content_type(r, "text/html");
    ap_rputs(DOCTYPE_HTML_3_2
             "<html>\n<head>\n<title>mod_telemetry: detail</title>\n</head>\n<body>\n \
<style type=\"text/css\"> \
body, td, p, div, small, big{ \
font-family: Arial, Helvetica, sans-serif \
} \
</style> ", r);
    /* server detail */
    up_time = (apr_uint32_t) apr_time_sec(nowtime -
                                          ap_scoreboard_image->global->
                                          restart_time);
    ap_rputs("<h1>mod_telemetry - HTTP response time report for ", r);
    ap_rvputs(r, ap_get_server_name(r), "</h1>\n\n", NULL);
    ap_rvputs(r, "<dl><dt>Server Version: ",
              ap_get_server_version(), "</dt>\n", NULL);
    ap_rvputs(r, "<dt>Server Built: ",
              ap_get_server_built(), "\n</dt></dl><hr /><dl>\n", NULL);
    ap_rvputs(r, "<dt>Current Time: ",
              ap_ht_time(r->pool, nowtime, DEFAULT_TIME_FORMAT, 0),
              "</dt>\n", NULL);
    ap_rvputs(r, "<dt>Restart Time: ",
              ap_ht_time(r->pool,
                         ap_scoreboard_image->global->restart_time,
                         DEFAULT_TIME_FORMAT, 0), "</dt>\n", NULL);
    ap_rprintf(r, "<dt>Parent Server Generation: %d</dt>\n",
               (int) ap_my_generation);
    ap_rputs("<dt>Server uptime: ", r);
    show_time(r, up_time);
    ap_rputs("</dt>\n", r);

    /* start our commands */
    ap_rputs("<P><a href=\"", r);
    ap_rputs(r->uri, r);
    ap_rputs("?reset\">[ Reset Counters ]</a>  | ", r);
    ap_rputs(" <a href=\"", r);
    ap_rputs(r->uri, r);

    /* retain argument list on refresh */
    if (r->args != NULL) {
        if (ap_strstr_c(r->args, "reset") == NULL) {
            ap_rputs("?", r);
            ap_rputs(r->args, r);
        }
    }
    ap_rputs("\">[ Refresh ] </a></p>", r);
    ap_rputs("<TABLE border=1 noshade>\n", r);

    /* table header */
    ap_rputs
      ("<TR><TH><a href=\"/tm?uri\">URI</a></TH><TH><a href=\"/tm?hits\">Hits</a></TH><TH><a href=\"/tm?last\">Last Time</a></TH><TH><a href=\"/tm?min\">Min Time(mS)</a></TH><TH><a href=\"/tm?max\">Max Time(mS)</a></TH><TH><a href=\"/tm?avg\">Avg Time(mS)</a></TH><th><a href=\"/tm?slow\">Slow Count</a></th><TH><a href=\"/tm?lastacc\">Last Access</a></TH>",r);

    /* dump codes */
    for (t=0; t < TM_CODES_TRACKED; t++)
      ap_rputs((char*) apr_psprintf(r->pool,"<TH>%d</TH>",telemetry_tracked_status[t]),r);
    ap_rputs("</TR>\n", r);

    /* dump total header */
    ap_rputs((char *) apr_psprintf(r->pool,"<TR><TD><B>Totals</B></TD><TD align=right>%d</TD><TD colspan=6>&nbsp;</td>",tmaggbase->hits),r);

    for (t=0; t < TM_CODES_TRACKED; t++)
     ap_rputs((char*) apr_psprintf(r->pool,"<TD align=right>%d</TD>",tmaggbase->resultcodetotals[t]),r);

    ap_rputs("</TR>\n",r);
    
    /* display the list */
    for (t = 0; t < totalrec; t++) {
        if (tmbase[index[t]].last > 0) {
            char last_s[APR_CTIME_LEN];
            apr_ctime(last_s, tmbase[index[t]].last);

            ap_rputs((char *) apr_psprintf(r->pool,
                                           "<TR><TD>%s</TD><TD ALIGN=RIGHT>%d</TD><TD ALIGN=RIGHT>%"
                                           APR_TIME_T_FMT
                                           "</TD><TD ALIGN=RIGHT>%"
                                           APR_TIME_T_FMT
                                           "</TD><TD ALIGN=RIGHT>%"
                                           APR_TIME_T_FMT
                                           "</TD><TD ALIGN=RIGHT>%"
                                           APR_TIME_T_FMT
                                           "</TD><TD>%d/%d/%d (%.2f%%)</TD><TD>%s</TD>\n",
                                           tmbase[index[t]].uri,
                                           tmbase[index[t]].hits,
                                           apr_time_as_msec(tmbase[index[t]].
                                                            lastdelta),
                                           apr_time_as_msec(tmbase[index[t]].
                                                            min),
                                           apr_time_as_msec(tmbase[index[t]].
                                                            max),
                                           apr_time_as_msec(tmbase[index[t]].
                                                            avg),
                                           tmbase[index[t]].slowsone,
                                           tmbase[index[t]].slowsfive,
                                           tmbase[index[t]].slowsten,
                                           (float) (100 *
                                                    ((float) tmbase[index[t]].
                                                     slowsone /
                                                     (float) tmbase[index[t]].
                                                     hits)), last_s), r);
	    /* dump codes */
	    for (ct=0; ct < TM_CODES_TRACKED; ct++)
	      ap_rputs((char*) apr_psprintf(r->pool,"<TD align=right>%d</TD>",tmbase[index[t]].resultcode[ct]),r);
	    ap_rputs("</TR>\n", r);

	}
    }

    ap_rputs("</table><P>" MOD_COPYRIGHT_STRING "</P></body></html>\n", r);
    return OK;
}


static int tm_report_csv(request_rec * r)
{
  /* Dump the URI Report */
  int t,ct;
  
  /* make an index of everything in memory */
  int index[sid];
  int indices = 0;
  int x;
  int totalrec = 0;
  apr_time_t nowtime;
  apr_interval_time_t up_time;
  
  nowtime = apr_time_now();
  
  ap_set_content_type(r, "text/plain");

  /* header line */
  ap_rputs("Total_Hits,",r);
  for (t=0; t < TM_CODES_TRACKED; t++) { 
    ap_rputs((char*) apr_psprintf(r->pool,"Result_Code_%d",telemetry_tracked_status[t]),r);
    if (t < TM_CODES_TRACKED-1) ap_rputs(",",r);
  }

  ap_rputs("\n",r);

  ap_rputs((char *) apr_psprintf(r->pool,"%d,",tmaggbase->hits),r);
  for (t=0; t < TM_CODES_TRACKED; t++) { 
    ap_rputs((char*) apr_psprintf(r->pool,"%d",tmaggbase->resultcodetotals[t]),r);
    if (t < TM_CODES_TRACKED-1) ap_rputs(",",r);
  }
  
  ap_rputs("\n",r);

  return OK;
}



static int modtelemetry_handle(request_rec * r)
{
    const char *timestr;
    struct timeval start;
    const char *loc;
    int i;

    apr_time_t t1 = apr_time_now();

    // store the start time in the module note field, we'll get this back later on.
    timestr = (char *) apr_psprintf(r->pool, "%" APR_TIME_T_FMT, t1);
    apr_table_set(r->notes, "tm_start", timestr);

#ifdef DEBUG
    fprintf(stderr, "req start: %s %s\n", r->uri, timestr);
    fflush(stderr);
#endif
    /* handle arguments */
    if (r->args) {
#ifdef DEBUG
        fprintf(stderr, "have args.");
        fflush(stderr);
#endif
        i = 0;
        while (telemetry_options[i].id != OPT_END) {
            if ((loc = ap_strstr_c(r->args,
                                   telemetry_options[i].form_data_str)) !=
                NULL) {
                switch (telemetry_options[i].id) {
                case OPT_RESET:
                    reset_counters(r->pool, r->server);
                    break;
                case OPT_SRT_URI:
                case OPT_SRT_HITS:
                case OPT_SRT_LASTDELTA:
                case OPT_SRT_MIN:
                case OPT_SRT_MAX:
                case OPT_SRT_AVG:
                case OPT_SRT_SLOW:
                case OPT_SRT_LASTACC:
                    /* change sort order */
                    sortby = telemetry_options[i].id;
                    break;
                }
            }
            i++;
        }
    }


    /* return OK if we're handling this... */
    if (strcmp(r->handler, "telemetry-status") == 0) {
      /* if url ends in /csv, they want human-readable. */
      if (strstr(r->uri,"/csv") != (r->uri + strlen(r->uri)-4))  {
	tm_report_detail(r);
      } else { 
	tm_report_csv(r);
      }
      return OK;
    }

    if (strcmp(r->handler, "telemetry-ipstatus") == 0) {
      /* they are requesting a human-readable report, by IP */
      tm_report_ip(r);
      return OK;
    }

    /* TODO: Add machine readable report */

    // Return DECLINED so that the Apache core will keep looking for
    // other modules to handle this request.  This effectively makes
    // this module completely transparent.

    return DECLINED;
}

/* Init The Module */
static int tminit(apr_pool_t * p, apr_pool_t * plog,
                  apr_pool_t * ptemp, server_rec * s)
{
    apr_status_t status;
    apr_size_t retsize;
    apr_size_t shm_size;
    void *shmstart;
    telem_data *tmstat;
    int t;

    /* These two help ensure that we only init once. */
    void *data;
    const char *userdata_key = "jn_shm_telem_module";

    /* Init APR's atomic functions */
    status = apr_atomic_init(p);
    if (status != APR_SUCCESS)
        return HTTP_INTERNAL_SERVER_ERROR;

    apr_pool_userdata_get(&data, userdata_key, s->process->pool);

    if (!data) {
        apr_pool_userdata_set((const void *) 1, userdata_key,
                              apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    shm_size = (apr_size_t) sizeof(telem_aggregate_data) +  (sizeof(telem_data) * sid);

    /* If there was a memory block already assigned.. destroy it */
    if (shm) {
        status = apr_shm_destroy(shm);
        if (status != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "mod_telemetry : Couldn't destroy old memory block\n");
            return status;
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "mod_telemetry : Old Shared memory block, destroyed.");
        }
    }

    /* Create shared memory block */
    status = apr_shm_create(&shm, shm_size, TM_SHM_FILENAME, p);
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                    "mod_telemetry : Error creating shm block\n");
        return status;
    }
    /* Check size of shared memory block - did we get what we asked for? */
    retsize = apr_shm_size_get(shm);
    if (retsize != shm_size) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "mod_telemetry : Error allocating shared memory block\n");
        return status;
    }

    /* Init shm block */
    retsize = apr_shm_size_get(shm);
    shmstart = apr_shm_baseaddr_get(shm);

    if (shmstart == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "mod_telemetry : Error creating SHM block.\n");
        return status;
    }

    /* the first record is the global record, so skip it. */
    tmaggbase = shmstart;
    tmbase    = shmstart + sizeof(telem_aggregate_data);

    reset_counters(p, s);

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                 "mod_telemetry : Version %s - Initialized [tracking: %d URIs max, %d IPs max]",
                 VERSION, TM_MAX_URIS,TM_MAX_IPS);

    return OK;
}

/*
 * This function is a callback and it declares what other functions
 * should be called for request processing and configuration requests.
 * This callback function declares the Handlers for other events.
 */
static void modtelemetry_register_hooks(apr_pool_t * p)
{
  // register the handler first and the log hook last so we get the complte time profile
  
  ap_hook_handler(modtelemetry_handle, NULL, NULL, APR_HOOK_FIRST);
  ap_hook_post_config(tminit, NULL, NULL,
		      APR_HOOK_MIDDLE);
  ap_hook_log_transaction(modtelemetry_log, NULL, NULL, APR_HOOK_LAST);
  
}

/* set mod enabled or disabled */
static const char *telemetrymodule(cmd_parms * cmd, void *dconf, int flag)
{
  telemetry_server_config *sconf;
  
  sconf =
    (telemetry_server_config *) ap_get_module_config(cmd->server->
						     module_config,
						     &telemetry_module);
  sconf->state = (flag ? TELEM_ENABLED : TELEM_DISABLED);

  return NULL;
}

static const char *telemetryimgfilter(cmd_parms * cmd, void *dconf, int flag)
{
  telemetry_server_config *sconf;
  
  sconf =
    (telemetry_server_config *) ap_get_module_config(cmd->server->
						     module_config,
						     &telemetry_module);
  sconf->imgfilter = (flag ? TELEM_ENABLED : TELEM_DISABLED);
  
  return NULL;
}


static const char *telemetryonlyvalid(cmd_parms * cmd, void *dconf, int flag)
{
  telemetry_server_config *sconf;
  
  sconf =
    (telemetry_server_config *) ap_get_module_config(cmd->server->
						     module_config,
						     &telemetry_module);
  sconf->onlyvalid = (flag ? TELEM_ENABLED : TELEM_DISABLED);
  
  return NULL;
}


static const char *telemetryjscssfilter(cmd_parms * cmd, void *dconf, int flag)
{
  telemetry_server_config *sconf;
  
  sconf =
    (telemetry_server_config *) ap_get_module_config(cmd->server->
						     module_config,
						     &telemetry_module);
  sconf->jscssfilter = (flag ? TELEM_ENABLED : TELEM_DISABLED);
  
  return NULL;
}

static const char *telemetryiptrack(cmd_parms * cmd, void *dconf, int flag)
{
  telemetry_server_config *sconf;
  
  sconf =
    (telemetry_server_config *) ap_get_module_config(cmd->server->
						     module_config,
						     &telemetry_module);
  sconf->iptrack = (flag ? TELEM_ENABLED : TELEM_DISABLED);
  
  return NULL;
}


static void *create_tm_server_config(apr_pool_t * p, server_rec * s)
{
  /* allocate server config and set defaults */
  telemetry_server_config *new;
  
  new =
    (telemetry_server_config *) apr_pcalloc(p,
					    sizeof
					    (telemetry_server_config));
  new->state = TELEM_ENABLED;
  new->imgfilter = TELEM_ENABLED;
  new->jscssfilter = TELEM_ENABLED;
  new->onlyvalid = TELEM_ENABLED;

  new->matchregexps = apr_array_make(p, 20, sizeof(tm_match_entry));  

  /* remember the pointer for later use - ugly, but no other way to get it */
  globalconf = new;
  return (void *) new;
}

/*
 * Declare and populate the module's data structure.  The
 * name of this structure ('telem_module') is important - it
 * must match the name of the module.  This structure is the
 * only "glue" between the httpd core and the module.
 */


/* command table */
static const command_rec tm_cmds[] = {
  AP_INIT_FLAG("TelemetryModule", telemetrymodule, NULL,
	       RSRC_CONF | ACCESS_CONF,
	       "On or Off to enable or disable (default) the telemetry module"),
  AP_INIT_FLAG("TelemetryFilterImages", telemetryimgfilter, NULL,
	       RSRC_CONF | ACCESS_CONF,
	       "On or Off to enable (Default) or disable data collection for files ending in .png/.jpg/.jpeg/.gif"),
  AP_INIT_FLAG("TelemetryFilterJSCSS", telemetryjscssfilter, NULL,
	       RSRC_CONF | ACCESS_CONF,
	       "On or Off to enable (Default) or disable data collection for files ending in .css/.js"),
  AP_INIT_FLAG("TelemetryOnlyValid", telemetryonlyvalid, NULL,
	       RSRC_CONF | ACCESS_CONF,
	       "If On (default), Only requests returning HTTP code 200 are tracked"),
  AP_INIT_TAKE1("TelemetryMatch", add_match_regex, NULL,
  	       RSRC_CONF | ACCESS_CONF,
  	       "A regexp representing a pattern of URIs to match. If any line matches, the URI will be tracked."),
  AP_INIT_FLAG("TelemetryIPTrack", telemetryiptrack, NULL,
	       RSRC_CONF | ACCESS_CONF,
	       "If On, tracks top IPs accessing the site, accessible by /topip"),
  {NULL}
};

module AP_MODULE_DECLARE_DATA telemetry_module = {
    // Only one callback function is provided.  Real
    // modules will need to declare callback functions for
    // server/directory configuration, configuration merging
    // and other tasks.
    STANDARD20_MODULE_STUFF,    /* Per dir config creator */
    NULL,                       /* dir config merger */
    NULL,                       /* dir merger */
    create_tm_server_config,    /* server config creator */
    NULL,                       /* merge svr config */
    tm_cmds,                    /* command table */
    modtelemetry_register_hooks,        /* callback for registering hooks */
};

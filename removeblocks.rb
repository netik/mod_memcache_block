#!/usr/bin/ruby
#
# construct the blocklist in memcache for testing
#

# for use with memcache-client 1.5.x

require 'rubygems'
require 'memcache'

@servers =  [ 'localhost:11211' ]

@options = {
      :prefix_key => '',
      :hash => :default,
      :distribution => :modula
}

@cache = MemCache.new(@servers,@options)
#
# per robey: marshall must be set to false otherwise we'll feed marshalled data to apache
# and apache doesn't work with marshalled data.
#
@cache.delete("mb:b:1")
@cache.delete("mb:b:2")
@cache.delete("mb:b:3")
@cache.delete("mb:b:4")

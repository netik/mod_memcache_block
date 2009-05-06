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
@cache.set("mb:b:1",'127.0.0.0-127.0.0.99',0,true)
@cache.set("mb:b:2",'127.0.0.0/24',0,true)
@cache.set("mb:b:3",'127.0.0.1',0,true)
# ipv6
@cache.set("mb:b:4",'::1',0,true)


# whitelist test
@cache.set("mb:w:4",'::1',0,true)

puts "blocks set:"
for x in 1..4 
    puts "#{x} = " + @cache.get("mb:b:#{x}",true)
end

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


for x in 1..4 
  @cache.delete("mb:b:#{x}")
end

puts "blocks deleted."


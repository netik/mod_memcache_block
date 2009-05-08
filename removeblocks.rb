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

# remove the blocks set by setblocks.rb
for x in 1..4 
  @cache.delete("mb:b:#{x}")
end

# remove our test whitelist entry
@cache.delete("mb:w:1")

puts "blocks deleted."


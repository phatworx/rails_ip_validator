# encoding: utf-8

require 'rubygems'
require 'bundler'
begin
  Bundler.setup(:default, :development)
rescue Bundler::BundlerError => e
  $stderr.puts e.message
  $stderr.puts "Run `bundle install` to install missing gems"
  exit e.status_code
end

require 'cover_me'
require 'minitest/autorun'
require 'minitest/mock'
require 'minitest/benchmark'
require 'minitest/spec'
require 'minitest/pride'


$LOAD_PATH.unshift(File.dirname(__FILE__))
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
require 'rails_ip_validator'

class MiniTest::Unit::TestCase
end
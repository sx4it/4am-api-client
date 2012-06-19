#! /usr/bin/ruby
# -*- coding: utf-8 -*-

##############################################################################
##
##              4am-shell
##

require 'rubygems'
require 'readline'
require 'parslet'
require 'pp'
require 'json'
require '4am-api.rb'

class Parser < Parslet::Parser
  rule(:word) { match['[:alnum:]|_'].repeat(1) }
  rule(:space) { match('\s').repeat(1) }
  rule(:space?) { space.maybe }
  rule(:comma) { str(',') >> space? }
  rule(:lparen) { str('(') >> space? }
  rule(:rparen) { str(')') >> space? }

  rule(:params) { (space? >> word.as(:param) >> space?).repeat }
  rule(:arglist) { word.as(:arg) >> (comma >> word.as(:arg)).repeat }

  rule(:object) {
        (
                space? >> str('=').as(:setter) >> space? >> word.as(:value)    |
                str('(') >> arglist >> str(')')
         ).repeat(0,1)
  }
  rule(:manip_user) { space? >> str("user-") >> word.as(:key) >> str('.') >> word.as(:method) >> object.as(:args) >> space? }
  rule(:manip_host) { space? >> str("host-") >> word.as(:key) >> str('.') >> word.as(:method) >> object.as(:args) >> space? }
  rule(:funcall) { space? >> word.as(:fname) >> space? >> params.as(:params)}
  rule(:nothing) { str('') }
  rule(:expression) {
    manip_user.as(:user) |
    manip_host.as(:host) |
    funcall.as(:funcall) |
    nothing
  }
  root :expression
end

# # retrieve the api token from the '.4am-credentials' file
# $api_token = YAML.load_file(File.expand_path("~/.4am-credentials.yaml"))['token']

# create a new client instance with the api token
$client = Client.new

# ignore sigint
trap('INT', 'SIG_IGN')

def ParseLine(data)
  request = {}

  if data[:funcall]
    request['type'] = "Client"
    request['fname'] = data[:funcall][:fname]
    request['params'] = []
    data[:funcall][:params].each do |elem|
      elem.each do |k, v|
        request['params'].push(v)
      end
    end

  elsif data[:user]
    puts data.inspect
    request['type'] = "User"
    request['fname'] = data[:user][:method]
    request['key'] = data[:user][:key]
    request['args'] = []
    data[:user][:args].each do |elem|
      elem.each do |k, v|
        if "#{v}" == "="
          request['fname'] += "="
        else
          request['args'].push(v)
        end
      end
    end

  elsif data[:host]
    request['type'] = "Host"
    request['fname'] = data[:host][:method]
    request['key'] = data[:host][:key]
    request['args'] = []
    data[:host][:args].each do |elem|
      elem.each do |k, v|
        if "#{v}" == "="
          request['fname'] += "="
        else
          request['args'].push(v)
        end
      end
    end    

  else
    puts "Unknown data."

  end
  request
end

$host = {}
$user = {}
$cmd = {}
$user_group = {}
$host_group = {}

while line = Readline.readline('4am-shell> ', true)
  data = Parser.new.parse(line)
  if data == ""; next; end
  api_call = ParseLine(data)
  puts api_call.inspect
  begin
    # Methods from 'Client' class
    if api_call['type'] == "Client"
      ret = $client.method(api_call['fname']).call(*api_call['params'])
      if ret.instance_of? Host
        $host["#{api_call['params'][0]}"] = ret
        puts ret.inspect
      elsif ret.instance_of? User
        $user["#{api_call['params'][0]}"] = ret
        puts ret.inspect        
      end
    # Methods from 'Host' class
    elsif api_call['type'] == "Host"
      $host["#{api_call['key']}"].method(api_call['fname']).call(*api_call['args'])
    # Methods from 'User' class
    elsif api_call['type'] == "User"
      $user["#{api_call['key']}"].method(api_call['fname']).call(*api_call['args'])        
    end
  # Handle errors here in a detailed way
  rescue NameError => e
    puts "Unknown api method '#{api_call['fname']}'."
  rescue TypeError => e
    puts e.message
  rescue ArgumentError => e
    puts e.message
  rescue RuntimeError => e
    puts e.message
  end
end

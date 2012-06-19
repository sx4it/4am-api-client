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
  rule(:space)  { match('\s').repeat }
  rule(:param) { word } 
  rule(:params) { (space >> param.as(:params) >> space).repeat }
  rule(:function) { space >> word.as(:function) >> space }
  rule(:expression) { function >> params }
  root :expression
end

# retrieve the api token from the '.4am-credentials' file
$api_token = YAML.load_file(File.expand_path("~/.4am-credentials.yaml"))['token']

# create a new client instance with the api token
$client = Client.new

# ignore sigint
trap('INT', 'SIG_IGN')

def ParseLine(data)
  funcall = {}
  funcall['params'] = []
  if data.length == 1
    funcall['fname'] = data[:function]
  else
    data.each do |elem|
      elem.each do |k, v|
        if "#{k}" == "function"
          funcall['fname'] = v
        else
          funcall['params'].push(v)
        end
      end
    end
  end
  funcall
end

$inst = {}

while line = Readline.readline('4am-shell> ', true)
  data = ParseLine(Parser.new.parse(line))
  puts data.inspect
  begin
    # On peut récupérer le retour...
    $client.method(data['fname']).call(*data['params'])
  rescue NameError => e
    puts "Unknown api method '#{data['fname']}'."
  rescue TypeError => e
    puts e.message
  rescue ArgumentError => e
    puts e.message
  rescue RuntimeError => e
    puts e.message
  end
end

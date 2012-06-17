#! /usr/bin/ruby

require 'rubygems'
require 'httparty'
require 'yaml'
require 'pp'
require 'json'
require 'redis'
require 'yam'

$api_token = YAML.load_file(File.expand_path("~/.4am-credentials.yaml"))['token']

class Entity
  def create (name, &block)
    self.class.send(:define_method, name, block)
  end

  def initialize options, var = {}
    @options = options
    var.each do |k, v|
      instance_variable_set("@#{k}", v)
      create("#{k}") do
        instance_variable_get("@#{k}")
      end
      create("#{k}=") do |v|
        instance_variable_set("@#{k}", v)
      end
    end
  end

  def to_h
    ret = {}
    ret[self.class.to_s.downcase] = Hash[*instance_variables.map do |w|
                                  [w[1..-1], instance_variable_get(w)]
                                end.flatten]
    ret[self.class.to_s.downcase].delete "options"
    ret
  end

end
 
#   clear_host_cmd_index DELETE /hosts/:host_id/cmd/clear(.:format)                cmd#clear
# refresh_host_cmd_index GET    /hosts/:host_id/cmd/refresh(.:format)              cmd#refresh
#               host_cmd POST   /hosts/:host_id/cmd/:id(.:format)                  cmd#new
#         host_cmd_index GET    /hosts/:host_id/cmd(.:format)                      cmd#index
#                        POST   /hosts/:host_id/cmd(.:format)                      cmd#create
#           new_host_cmd GET    /hosts/:host_id/cmd/new(.:format)                  cmd#new
#          edit_host_cmd GET    /hosts/:host_id/cmd/:id/edit(.:format)             cmd#edit
#                        GET    /hosts/:host_id/cmd/:id(.:format)                  cmd#show
#                        PUT    /hosts/:host_id/cmd/:id(.:format)                  cmd#update
#                        DELETE /hosts/:host_id/cmd/:id(.:format)                  cmd#destroy

#                  hosts GET    /hosts(.:format)                                   hosts#index
#                        POST   /hosts(.:format)                                   hosts#create
#               new_host GET    /hosts/new(.:format)                               hosts#new
#              edit_host GET    /hosts/:id/edit(.:format)                          hosts#edit
#                   host GET    /hosts/:id(.:format)                               hosts#show
#                        PUT    /hosts/:id(.:format)                               hosts#update
#                        DELETE /hosts/:id(.:format)                               hosts#destroy
class Host < Entity
  include HTTParty
  base_uri 'http://dev2.sx4it.com:42164/hosts'
  attr_accessor :host_tpl_id, :created_at, :updated_at, :name, :ip, :id

  def show
    puts JSON.pretty_generate(self.to_h)
  end

  def cmds
    self.class.get("/#{self.id}/cmd.json", @options).parsed_response
  end

  def show_all_cmds
    self.cmds.each do |c|
      puts JSON.pretty_generate(c)
    end
  end

  def show_cmd(id)
    self.cmds.each do |c|
      if c['id'] == id
        puts JSON.pretty_generate(c)
      end
    end
  end

  def delete_cmd(id)
    self.cmds.each do |c|
      if c['id'] == id
        self.class.delete("/#{self.id}/cmd/#{id}.json", @options.merge(:body => {:host_id => @id, :id => id}))
      end
    end
  end

  def execute_cmd(id)
    self.class.get("/#{self.id}/cmd/new.json?command_id=#{id}", @options)
  end

  def stop_cmd(id)
    self.class.put("/#{self.id}/cmd/#{id}.json", @options.merge(:body => {:host_id => @id, :id => id}))
  end

  def refresh
    self.class.get("/#{self.id}/cmd/refresh.json", @options)
  end
  
  def clear_finished
    self.class.delete("/#{self.id}/cmd/clear.json", @options)
  end
  
  def save
    self.class.put("/#{self.id}.json", @options.merge(:body => self.to_h))
  end
end

class User < Entity
  include HTTParty
  base_uri 'http://dev2.sx4it.com:42164/users'
end

class Client
  include HTTParty
  base_uri 'http://dev2.sx4it.com:42164'

  def initialize(u=$api_token, p=nil)
    @auth = {:username => u, :password => p}
    @options = {
      :basic_auth => @auth,
      :format => :json,
     ## :headers => {
     ##   "Content-Type" => "application/json",
     ##   "content-type" => "application/json",
     ##   "Accept" => "application/json"
     ## }
    }
  end

  def users
    self.class.get("/users.json", @options).parsed_response
  end

  def hosts
    self.class.get('/hosts.json', @options).parsed_response
  end

  def cmds
    self.class.get('/commands.json', @options).parsed_response
  end

  def show_hosts
    self.hosts.each do |host|
      puts host['name']
    end
  end

  def get_host(name)
    self.hosts.each do |host|
      if "#{host['name']}" == "#{name}"
        return Host.new @options, host
      end
    end
    raise 'host not found'
  end

end

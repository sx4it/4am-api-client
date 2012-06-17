#! /usr/bin/ruby

require 'rubygems'
require 'httparty'
require 'yaml'
require 'pp'
require 'json'
require 'redis'

$api_token = ''

class Entity
  def create (name, &block)
    self.class.send(:define_method, name, block)
  end

  def initialize var = {}
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
    ret[self.class.to_s] = Hash[*instance_variables.map do |w|
                                  [w[1..-1], instance_variable_get(w)]
                                end.flatten]
  end

end
 
class Host < Entity
  include HTTParty
  base_uri 'http://dev2.sx4it.com:42164'
  attr_accessor :host_tpl_id, :created_at, :updated_at, :name, :ip, :id

  def show
    puts JSON.pretty_generate(self.to_h)
  end

#              clear_host_cmd_index GET    /hosts/:host_id/cmd/clear(.:format)                cmd#clear
#            refresh_host_cmd_index GET    /hosts/:host_id/cmd/refresh(.:format)              cmd#refresh
#                    host_cmd_index GET    /hosts/:host_id/cmd(.:format)                      cmd#index
#                                   POST   /hosts/:host_id/cmd(.:format)                      cmd#create
#                      new_host_cmd GET    /hosts/:host_id/cmd/new(.:format)                  cmd#new
#                     edit_host_cmd GET    /hosts/:host_id/cmd/:id/edit(.:format)             cmd#edit
#                          host_cmd GET    /hosts/:host_id/cmd/:id(.:format)                  cmd#show
#                                   PUT    /hosts/:host_id/cmd/:id(.:format)                  cmd#update
#                                   DELETE /hosts/:host_id/cmd/:id(.:format)                  cmd#destroy

  def cmds
    options = { :basic_auth => { :username => $api_token, :password => nil } }
    self.class.get("/hosts/"+"#{self.id}"+"/cmd.json", options).parsed_response
  end

  def show_all_cmds
    self.cmds.each do |c|
      puts JSON.pretty_generate(c)
    end
  end

  def delete_cmd(id)
    self.cmds.each do |c|
      if c['id'] == id
        options = { :basic_auth => { :username => $api_token, :password => nil } }
        self.class.delete("/hosts/"+"#{self.id}"+"/cmd/"+"#{id}"+".json", options)
      end
    end
  end

  def execute_cmd(id)
    opts_get = { :basic_auth => { :username => $api_token, :password => nil } }
    response = self.class.get("/hosts/"+"#{self.id}"+"/cmd.json", opts_get)
    # puts response.header, response.body
    # response.body.inspect
    # Create the data structure of the desired command
    cmd = {}
    cmd['time'] = Time.now
    cmd['status'] = "started"
    cmd['log'] = "-"
    cmd['type'] = "cmd-host"
    cmd['hosts'] = [self.to_h]
    cmd['hosts_ip'] = [@ip]
    cmd['hosts_id'] = [@id]
    # Get the command data to the corresponding id
    self.class.get("/commands.json", opts_get).parsed_response.each do |c|
      if c['id'] == id
        cmd['command'] = c
        cmd['script'] = c['command']
      end
    end
    # Get the user data corresponding to the user launching the cmd
    # -> TODO: find a way to retrieve the current user
    self.class.get("/users.json", opts_get).parsed_response.each do |u|
      if "#{u['login']}" == "martial" 
        cmd['current_user'] = u
      end
    end
    
    # Create the post body
    # puts JSON.pretty_generate(JSON.parse(response.body))
    # puts response.body
    body = JSON.parse(response.body)
    body[body.length] = cmd
    puts JSON.dump(body)

    # body.to_json.inspect
    # # puts JSON.pretty_generate(body)
    opts_post = {
      :basic_auth => { :username => $api_token, :password => nil },
      :body => body.to_json.to_s,
      :format => :json,
      :headers => {
        "Content-Type" => "application/json",
        "content-type" => "application/json",
        "Accept" => "application/json"
      }
    }
    opts_post.inspect
    #self.class.post("/hosts/"+"#{self.id}"+"/cmd.json", opts_post)
  end
  
  def save
    options = {
      :basic_auth => { :username => $api_token, :password => nil },
      :body => {
        :host_tpl_id => @host_tpl_id,
        :created_at => @created_at,
        :updated_at => @updated_at,
        :name => @name,
        :ip => @ip,
        :id => @id
      }.to_json,
      :format => :json,
      :headers => {
        "Content-Type" => "application/json",
        "content-type" => "application/json",
        "Accept" => "application/json"
      }
    }
    options.inspect
    # self.class.put("/hosts/"+"#{self.id}"+".json", options)
  end
end

class Client
  include HTTParty
  base_uri 'http://dev2.sx4it.com:42164'

  def initialize(u, p=nil)
    @auth = {:username => u, :password => p}
    $api_token = u
  end

  def users
    options = { :basic_auth => @auth }    
    self.class.get("/users.json", options).parsed_response
  end

  def hosts
    options = { :basic_auth => @auth }
    self.class.get('/hosts.json', options).parsed_response
  end

  def cmds
    options = { :basic_auth => @auth }
    self.class.get('/commands.json', options).parsed_response
  end

  def show_hosts
    self.hosts.each do |host|
      puts host['name']
    end
  end

  def get_host(name)
    self.hosts.each do |host|
      if "#{host['name']}" == "#{name}"
        return Host.new host
      end
    end
  end

  # ##
  # ## Faire plus generique pour les fonctions put/post
  # ## genre si besoin d'autres type de headers etc
  # ##
  # def post(request)
  #   options = {
  #     :basic_auth => @auth,
  #     :body => request['body'],
  #     :format => :json,
  #     :headers => {
  #       "Content-Type" => "application/json",
  #       "content-type" => "application/json",
  #       "Accept" => "application/json"
  #     }
  #   }
  #   self.class.post(request['end_point'], options)
  # end

  # def put(request)
  #   options = {
  #     :basic_auth => @auth,
  #     :body => request['body'],
  #     :format => :json,
  #     :headers => {
  #       "Content-Type" => "application/json",
  #       "content-type" => "application/json",
  #       "Accept" => "application/json"
  #     }
  #   }
  #   self.class.put(request['end_point'], options)
  # end

end

# config = YAML.load_file('4am-credential.yaml')
# puts "good token"
# client = Client.new config['valid_token'] #this is my token
# puts client.ShowHosts
# puts "good login"
# client = Client.new config['valid_user']['login'], config['valid_user']['password']
# puts client.hosts
# puts "bad login"
# client = Client.new config['invalid_user']['login'], config['invalid_user']['password']
# puts client.hosts
# puts "bad token"
# client = Client.new config['invalid_token']
# puts client.hosts

# routes :
#                               log GET    /log(.:format)                                     log#index
#                    new_user_index POST   /new_user(.:format)                                new_user#create
#                      new_new_user GET    /new_user/new(.:format)                            new_user#new
#                         host_acls GET    /host_acls(.:format)                               host_acls#index
#                                   POST   /host_acls(.:format)                               host_acls#create
#                          host_acl DELETE /host_acls/:id(.:format)                           host_acls#destroy
#                             roles GET    /roles(.:format)                                   roles#index
#                                   POST   /roles(.:format)                                   roles#create
#                              role DELETE /roles/:id(.:format)                               roles#destroy
#                       admin_roles GET    /admin/roles(.:format)                             admin/roles#index
#                                   POST   /admin/roles(.:format)                             admin/roles#create
#                        admin_role DELETE /admin/roles/:id(.:format)                         admin/roles#destroy
#               add_role_admin_user POST   /admin/users/:id/add_role(.:format)                admin/users#add_role
#            delete_role_admin_user DELETE /admin/users/:id/delete_role(.:format)             admin/users#delete_role
#                       admin_users GET    /admin/users(.:format)                             admin/users#index
#                                   POST   /admin/users(.:format)                             admin/users#create
#                    new_admin_user GET    /admin/users/new(.:format)                         admin/users#new
#                   edit_admin_user GET    /admin/users/:id/edit(.:format)                    admin/users#edit
#                        admin_user GET    /admin/users/:id(.:format)                         admin/users#show
#                                   PUT    /admin/users/:id(.:format)                         admin/users#update
#                                   DELETE /admin/users/:id(.:format)                         admin/users#destroy
#               add_user_user_group GET    /user_groups/:id/add_user(.:format)                user_groups#add_user
#               del_user_user_group GET    /user_groups/:id/del_user(.:format)                user_groups#del_user
#                       user_groups GET    /user_groups(.:format)                             user_groups#index
#                                   POST   /user_groups(.:format)                             user_groups#create
#                    new_user_group GET    /user_groups/new(.:format)                         user_groups#new
#                   edit_user_group GET    /user_groups/:id/edit(.:format)                    user_groups#edit
#                        user_group GET    /user_groups/:id(.:format)                         user_groups#show
#                                   PUT    /user_groups/:id(.:format)                         user_groups#update
#                                   DELETE /user_groups/:id(.:format)                         user_groups#destroy
#                          commands GET    /commands(.:format)                                commands#index
#                                   POST   /commands(.:format)                                commands#create
#                       new_command GET    /commands/new(.:format)                            commands#new
#                      edit_command GET    /commands/:id/edit(.:format)                       commands#edit
#                           command GET    /commands/:id(.:format)                            commands#show
#                                   PUT    /commands/:id(.:format)                            commands#update
#                                   DELETE /commands/:id(.:format)                            commands#destroy
#            autocomplete_host_name GET    /autocomplete_host_name(.:format)                  autocomplete#autocomplete_host_name
#           autocomplete_user_login GET    /autocomplete_user_login(.:format)                 autocomplete#autocomplete_user_login
#              clear_host_cmd_index GET    /hosts/:host_id/cmd/clear(.:format)                cmd#clear
#            refresh_host_cmd_index GET    /hosts/:host_id/cmd/refresh(.:format)              cmd#refresh
#                    host_cmd_index GET    /hosts/:host_id/cmd(.:format)                      cmd#index
#                                   POST   /hosts/:host_id/cmd(.:format)                      cmd#create
#                      new_host_cmd GET    /hosts/:host_id/cmd/new(.:format)                  cmd#new
#                     edit_host_cmd GET    /hosts/:host_id/cmd/:id/edit(.:format)             cmd#edit
#                          host_cmd GET    /hosts/:host_id/cmd/:id(.:format)                  cmd#show
#                                   PUT    /hosts/:host_id/cmd/:id(.:format)                  cmd#update
#                                   DELETE /hosts/:host_id/cmd/:id(.:format)                  cmd#destroy
#                             hosts GET    /hosts(.:format)                                   hosts#index
#                                   POST   /hosts(.:format)                                   hosts#create
#                          new_host GET    /hosts/new(.:format)                               hosts#new
#                         edit_host GET    /hosts/:id/edit(.:format)                          hosts#edit
#                              host GET    /hosts/:id(.:format)                               hosts#show
#                                   PUT    /hosts/:id(.:format)                               hosts#update
#                                   DELETE /hosts/:id(.:format)                               hosts#destroy
#               add_host_host_group GET    /host_groups/:id/add_host(.:format)                host_groups#add_host
#               del_host_host_group GET    /host_groups/:id/del_host(.:format)                host_groups#del_host
#        clear_host_group_cmd_index GET    /host_groups/:host_group_id/cmd/clear(.:format)    cmd#clear
#              host_group_cmd_index GET    /host_groups/:host_group_id/cmd(.:format)          cmd#index
#                                   POST   /host_groups/:host_group_id/cmd(.:format)          cmd#create
#                new_host_group_cmd GET    /host_groups/:host_group_id/cmd/new(.:format)      cmd#new
#               edit_host_group_cmd GET    /host_groups/:host_group_id/cmd/:id/edit(.:format) cmd#edit
#                    host_group_cmd GET    /host_groups/:host_group_id/cmd/:id(.:format)      cmd#show
#                                   PUT    /host_groups/:host_group_id/cmd/:id(.:format)      cmd#update
#                                   DELETE /host_groups/:host_group_id/cmd/:id(.:format)      cmd#destroy
#                       host_groups GET    /host_groups(.:format)                             host_groups#index
#                                   POST   /host_groups(.:format)                             host_groups#create
#                    new_host_group GET    /host_groups/new(.:format)                         host_groups#new
#                   edit_host_group GET    /host_groups/:id/edit(.:format)                    host_groups#edit
#                        host_group GET    /host_groups/:id(.:format)                         host_groups#show
#                                   PUT    /host_groups/:id(.:format)                         host_groups#update
#                                   DELETE /host_groups/:id(.:format)                         host_groups#destroy
#                         host_tpls GET    /host_tpls(.:format)                               host_tpls#index
#                                   POST   /host_tpls(.:format)                               host_tpls#create
#                      new_host_tpl GET    /host_tpls/new(.:format)                           host_tpls#new
#                     edit_host_tpl GET    /host_tpls/:id/edit(.:format)                      host_tpls#edit
#                          host_tpl GET    /host_tpls/:id(.:format)                           host_tpls#show
#                                   PUT    /host_tpls/:id(.:format)                           host_tpls#update
#                                   DELETE /host_tpls/:id(.:format)                           host_tpls#destroy
#                              keys GET    /keys(.:format)                                    keys#index
#                                   POST   /keys(.:format)                                    keys#create
#                           new_key GET    /keys/new(.:format)                                keys#new
#                          edit_key GET    /keys/:id/edit(.:format)                           keys#edit
#                               key GET    /keys/:id(.:format)                                keys#show
#                                   PUT    /keys/:id(.:format)                                keys#update
#                                   DELETE /keys/:id(.:format)                                keys#destroy
#                             login GET    /login(.:format)                                   sessions#new
#                                   POST   /login(.:format)                                   sessions#create
#                            logout GET    /logout(.:format)                                  sessions#destroy
#                         keys_user GET    /users/:id/keys(.:format)                          users#keys
#                     add_role_user POST   /users/:id/add_role(.:format)                      users#add_role
#                  delete_role_user DELETE /users/:id/delete_role(.:format)                   users#delete_role
#                             users GET    /users(.:format)                                   users#index
#                                   POST   /users(.:format)                                   users#create
#                          new_user GET    /users/new(.:format)                               users#new
#                         edit_user GET    /users/:id/edit(.:format)                          users#edit
#                              user GET    /users/:id(.:format)                               users#show
#                                   PUT    /users/:id(.:format)                               users#update
#                                   DELETE /users/:id(.:format)                               users#destroy
#                              root        /                                                  dashboard#index
#         graph_authorization_rules GET    /authorization_rules/graph(.:format)               authorization_rules#graph
#        change_authorization_rules GET    /authorization_rules/change(.:format)              authorization_rules#change
#suggest_change_authorization_rules GET    /authorization_rules/suggest_change(.:format)      authorization_rules#suggest_change
#               authorization_rules GET    /authorization_rules(.:format)                     authorization_rules#index
#              authorization_usages GET    /authorization_usages(.:format)                    authorization_usages#index

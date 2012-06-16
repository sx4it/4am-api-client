#! /usr/bin/ruby

require 'rubygems'
require 'httparty'
require 'json'

class Host
  attr_accessor :host_tpl_id, :created_at, :updated_at, :name, :ip, :id
  
  def initialize(hash = {})
    hash.each do |k, v|
      self.instance_variable_set("@#{k}", v)
    end
  end

  def get_json
    dup = self.dup
    dup.host_tpl_id = @host_tpl_id
    dup.created_at = @created_at
    dup.updated_at = @updated_at 
    dup.name = @name
    dup.ip = @ip
    dup.id = @id
    dup.to_json
  end

  def show
    puts JSON.pretty_generate(self.get_json)
  end
end

class Client
  include HTTParty
  base_uri 'http://dev2.sx4it.com:42164'

  def initialize(u, p=nil)
    @auth = {:username => u, :password => p}
  end

  def hosts
    options = { :basic_auth => @auth }
    self.class.get('/hosts.json', options).parsed_response
  end

  def ShowHosts
    options = { :basic_auth => @auth }
    self.hosts.each do |host|
      puts host['name']
    end
  end

  def GetHost(name)
    options = { :basic_auth => @auth }
    self.hosts.each do |host|
      if "#{host['name']}" == "#{name}"
        return Host.new host
      end
    end
  end

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

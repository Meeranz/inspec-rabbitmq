#Checking for os name,family, release version and arch.
family = os[:family]
name = os[:name]
release = os[:release] 
arch = os[:arch]
 
if family=='debian' && name=='ubuntu' && release=='16.04' && arch=='x86_64'
then
path = '/etc/rabbitmq'
rabbitmq_path = File.join(path,'rabbitmq.config')
service ='/lib/systemd/system'
rabbitmq_service =File.join(service,'rabbitmq-server.service')

control "rabbitmq" do
impact 1.0	

#checking whether the rabbitmq service is installed,enabled and is running 
describe service('rabbitmq-server') do
   it { should be_installed }
   it { should be_enabled }
   it { should be_running }
end

#checking for the rabbitmq-server version
describe command('dpkg -s rabbitmq-server | grep Version') do
   its('stdout') { should eq "Version: 3.6.14-1\n" }
   its('exit_status') { should eq 0 }
end
#checking the passwd file for the uid and gid 
File.open('/etc/passwd').each do |line|
if line .include? "rabbitmq"
user= line
users=user.split(":")
uid=users[2]
gid=users[3]
if(describe passwd()do
  its('users') { should include 'rabbitmq' }
 end)
describe passwd.users('rabbitmq') do
its('uids') { should include uid }
its('gids') { should include gid }
end
end
end
end

describe user('rabbitmq') do
#check the passwd file inside etc directory for the user security
#checking the passwd file in etc/passwd
   it { should exist }
  its('group') { should eq 'rabbitmq' }
   its('home') { should eq '/var/lib/rabbitmq'}
   its('shell') { should eq '/bin/false' }
end

#checking the permissions for the rabbitmq-server.service
describe file(rabbitmq_service) do
    it {should be_file}
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    it { should be_readable.by('others')}
    it { should_not be_writable.by('others') }
    it { should_not be_executable.by('others') }
end
describe file(rabbitmq_service) do
#desc "checking the contents of rabbitmq-server.service"
its ('content') { should match 'User=rabbitmq'}
its ('content') { should match 'Group=rabbitmq'}
its ('content') { should match 'RestartSec=10'}
its ('content') { should match 'TimeoutStartSec=3600'}
its ('content'){ should match 'WorkingDirectory=/var/lib/rabbitmq'}
its ('content'){ should match 'ExecStart=/usr/lib/rabbitmq/bin/rabbitmq-server'}
its ('content'){ should match 'ExecStop=/usr/lib/rabbitmq/bin/rabbitmqctl stop'}
end

describe command('rabbitmqctl').exist? do
   it { should eq true }
end
 
describe host('localhost', port:15672, protocol: 'icmp') do
   it { should be_reachable } #to verify the hostname is reachable over specific protocol and port number
   #to verify that the specific ipaddress is resolvable
   it { should be_resolvable }  
   its('ipaddress') {should include '127.0.0.1'}

end

end

control "rabbitmq-config" do
impact 1.0
#checking whether the port 15672 is listening and tcp protocol is used or not
describe port(15672) do
   it {should be_listening}
   its('protocols') { should cmp 'tcp' }
end
#checking the rabbitmq-server directory
describe file('/usr/share/doc/rabbitmq-server/') do
   it { should exist }
   it { should be_owned_by 'root' }
   its ('mode') {should cmp '0755'}
   it {should be_directory}
end  

end

control "config_file_check" do
impact 1.0
describe file('/etc/rabbitmq/rabbitmq.config') do
 #checking the config file permissions
   it { should be_owned_by 'root' } 
   it { should exist }
   it { should be_file }
   its ('mode') { should cmp '0666' }
   it {should be_readable}
   it {should be_writable}  
   it {should be_readable.by('others')}
 
end
end
#=begin
control "config_check" do
title "checking the configurations of the rabbitmq.config file"
impact 1.0
#the default value is 1 but it is set to 8 in the config file so that more connections can be processed at a time
describe rabbitmq_config.params('rabbit', 'num_ssl_acceptors') do
   it {should eq 8}
end
describe rabbitmq_config.params('rabbit', 'num_tcp_acceptors') do
   it {should eq 10}
end
#ssl_listener and tcp_listener ports are checked
describe rabbitmq_config.params('rabbit', 'ssl_listeners') do
   it {should cmp 5671}
end
describe rabbitmq_config.params('rabbit', 'tcp_listeners') do
   it {should cmp 5672}
end
describe rabbitmq_config.params('rabbit', 'ssl_handshake_timeout') do
   it {should cmp 5000}
end
#checking the config that only errors are stored in the log file
describe rabbitmq_config.params('rabbit', 'log_levels','connection') do
   it {should cmp 'error'}
end
#specifies the memory threshold at which the flow control is triggered. we can also set this in memory units also as absolute 1024m
describe rabbitmq_config.params('rabbit','vm_memory_high_watermark' ) do
   it {should cmp 0.4}
end
#specifies the disk free limit 
describe rabbitmq_config.params('rabbit','disk_free_limit','mem_relative' ) do
   it {should cmp 2.0}
end
#checks the maximum number of channels per connection (here 0 means no limit)
describe rabbitmq_config.params('rabbit','channel_max') do
   it {should cmp 0}
end
#net_ticktime has has been set to 120 will make the cluster more resilient to short network outages
describe rabbitmq_config.params('kernal','net_ticktime') do
   it {should cmp 120}
end
#prefetch count for single fast consumer is more than 20, for multiple fast consumer is between 20 and 30 and for slow customer is 1 (prefetch is the amount limit of unacknowledged messages)
describe rabbitmq_config.params('rabbitmq_shovel','shovels','prefetch_count') do
   it {should cmp 20}
end

end

#checking the contents of shadow file (etc/shadow)
control 'shadow' do
title "password details"
describe shadow.users('root') do
  its('count') { should eq 1 }
  its('passwords') {should eq ['!']}
end
describe shadow.filter(user:'rabbitmq') do
   its('count') { should eq 1 }
end
describe shadow.users('rabbitmq') do
   its('warn_days') { should include '7' }
   its('max_days') { should include '99999' }   
   its('min_days') { should include '0' }
   its('last_changes') { should include '17521'}
   its('inactive_days') { should include nil }
   its('expiry_dates') { should include nil }
end
#checking that validity of the cert.pem is greater than 30
describe x509_certificate('/etc/ssl/cert.pem') do
  its('validity_in_days') { should be > 30 }
end

end
end

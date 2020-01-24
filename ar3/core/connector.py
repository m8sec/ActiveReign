from ar3.helpers.misc import get_ip

class Connector():
    def __init__(self, args, loggers, host):
        self.lmhash     = ''
        self.nthash     = ''

        # Loggers
        self.loggers    = loggers
        self.logger     = loggers['console']
        self.filer      = loggers[args.mode]

        # Authentication
        self.args       = args
        self.username   = args.user
        self.password   = args.passwd
        self.hash       = args.hash
        self.local_auth = args.local_auth
        self.domain     = args.domain
        self.debug      = args.debug
        self.timeout    = args.timeout


        # Target Host
        self.host = host
        if not self.host:
            self.host = self.domain
        self.ip = get_ip(self.host)

        # Domain
        if self.local_auth:
            self.domain = self.host

        # Hash Authentication
        if self.hash:
            try:
                self.lmhash, self.nthash = self.hash.split(':')
            except:
                self.nthash = self.hash
            self.password = ''

        # Vars displayed during enumeration, populated by class obj
        self.os         = ''
        self.os_arch    = ''
        self.signing    = ''
        self.smbv1      = ''
        self.srvdomain  = ''
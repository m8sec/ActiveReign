from ar3.helpers.misc import get_ip

class Connector():
    def __init__(self, args, loggers, host):
        self.lmhash     = ''
        self.nthash     = ''

        self.logger     = loggers['console']
        self.filer      = loggers[args.mode]

        self.host       = host
        self.args       = args
        self.ip         = get_ip(self.host)
        self.username   = args.user
        self.password   = args.passwd
        self.hash       = args.hash
        self.local_auth = args.local_auth
        self.domain     = args.domain
        self.debug      = args.debug
        self.timeout    = args.timeout

        if not self.host:
            self.host = self.domain

        if self.local_auth:
            self.domain = self.host

        if self.hash:
            try:
                self.lmhash, self.nthash = self.hash.split(':')
            except:
                self.nthash = self.hash
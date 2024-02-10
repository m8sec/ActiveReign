from os import _exit
from ar3.logger import highlight


class LockoutTracker():
    def __init__(self, args, loggers):
        self.username   = args.user
        self.domain     = args.domain
        self.localauth  = args.local_auth
        self.logger     = loggers['console']
        self.reporter   = loggers[args.mode]

        self.password = args.passwd
        if args.hash:
            self.password = args.hash

        self.threshold = args.lockout_threshold
        self.locked = 0

    def add_attempt(self):
        if not self.localauth:
            self.locked += 1
            # Will shutdown when 1 away from locking account
            if self.locked >= (self.threshold-1):
                self.logger.warning([ "Lockout Tracker", "{}\{} approaching threshold ({}\{}), closing...".format(self.domain,self.username, self.locked, self.threshold)])
                _exit(1)

    def failed_login(self, host, error):
        if "account_locked_out" in error:
            self.logger.warning([host, host, "Lockout Tracker", highlight("Account Locked: {}\{}".format(self.domain, self.username), 'red')])
            _exit(1)
        elif "access_denied" in error:
            self.logger.verbose([host, host, "LOCKOUT TRACKER", highlight("Access Denied: Insufficient privileges (User: \"{}\":\"{}\")".format(self.username, self.password), 'red')])
        else:
            self.logger.verbose([host, host, "LOCKOUT TRACKER", highlight(error, 'red')])
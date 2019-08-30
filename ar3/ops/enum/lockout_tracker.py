from os import _exit
from ar3.core.connector import Connector


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
                self.logger.warning([ "Lockout Tracker", "Account {}\{} one away from lockout threshold: {}\{}, closing...".format(self.domain,self.username, self.locked, self.threshold)])
                _exit(1)

    def failed_login(self, host, error):
        if "password_expired" in error:
            self.logger.success2([host, "", "LOCKOUT TRACKER", "{}\\{}:{}".format(self.domain, self.username, self.password), "\t\033[1;31mPassword Expired\033[0m"])
            self.reporter.info("Lockout Tracker\t{}\t{}\\{}\t{}\tPassword Expired".format(host, self.domain, self.username, self.password))
            _exit(1)

        elif "account_locked_out" in error:
            self.logger.warning([host, "", "LOCKOUT TRACKER", "{}\\{}:{}".format(self.domain, self.username, self.password), "\t\033[1;31mAccount Locked\033[0m"])
            self.reporter.info("Lockout Tracker\t{}\t{}\\{}\t{}\tAccount Locked".format(host, self.domain, self.username, self.password))
            _exit(1)

        elif "logon_failure" in error:
            self.add_attempt()
            self.logger.verbose([host, "", "LOCKOUT TRACKER", "{}\\{}:{}".format(self.domain, self.username, self.password), "\t\033[1;31mLogin Failed\033[0m"])

        else:
            self.logger.verbose([host, "", "LOCKOUT TRACKER", "{}\\{}:{}".format(self.domain, self.username, self.password), "\t\033[1;31m{}\033[0m".format(error)])
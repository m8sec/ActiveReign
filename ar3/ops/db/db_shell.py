import os
import logging
from cmd import Cmd

from ar3.ops.db import db_query
from ar3.ops.db.db_core import Ar3db
from ar3.logger import setup_logger

class AR3DBSHELL(Cmd):
    def __init__(self, logger):
        super(AR3DBSHELL, self).__init__()
        self.prompt     = "AR3DB> "
        self.logger     = logger

        self.workspace      = 'default'
        self.workspace_path = os.path.join(os.path.expanduser('~'), '.ar3', 'workspaces')
        self.db = Ar3db(self.workspace, self.logger, False)


    def do_workspace(self, args):
        if args == "list":
            for x in os.listdir(self.workspace_path):
                self.logger.output(x)

        elif args:
            if os.path.exists(self.workspace_path + "/{}".format(args)):
                self.workspace = args
                self.db = Ar3db(self.workspace, self.logger, False)
                self.logger.success("Workspace changed successfully: {}".format(args))

            else:
                self.logger.fail("Invalid workspace provided: Use \"workspace list\" for more")
        else:
            self.logger.fail("No workspace provided:")
            self.logger.output("    List Workspaces   : \"workspace list\"")
            self.logger.output("    Change Workspaces : \"workspace demo.local\"")

    def do_users(self, args):
        if args:
            db_query.user_lookup(self.db, self.logger, args)
        else:
            db_query.users(self.db, self.logger)

    def do_creds(self, args):
        if args:
            db_query.user_lookup(self.db, self.logger, args)
        else:
            db_query.creds(self.db, self.logger)

    def do_groups(self, args):
        if args:
            db_query.group_lookup(self.db, self.logger, args)
        else:
            db_query.groups(self.db, self.logger)

    def do_hosts(self, args):
        if args:
            db_query.host_lookup(self.db, self.logger, args)
        else:
            db_query.hosts(self.db, self.logger)

    def do_domains(self, args):
        db_query.domains(self.db, self.logger)

    def do_exit(self, args):
        raise SystemExit

def shell(logger):
    while True:
        try:
            shell = AR3DBSHELL(logger)
            shell.cmdloop()
        except Exception as e:
            logger.warning("AR3DB shell error: {}".format(str(e)))

def main():
    logger = setup_logger(logging.INFO, 'ar3')
    shell(logger)
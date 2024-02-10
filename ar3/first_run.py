import os
import sys
from shutil import copyfile

from ar3.ops.db.db_core import Ar3db
from ar3.modules import get_module_resources

def first_run_check(logger):
    if not os.path.exists(os.path.join(os.path.expanduser('~'), '.ar3')) or "--refresh" in sys.argv:
        first_run(logger)

def first_run(logger):
    LOG_DIR = os.path.join(os.path.expanduser('~'), '.ar3')

    logger.status('Welcome to Active Reign, please hold while we setup your system..')
    logger.status("Creating ActiveReign directories")

    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

    for folder in ['certs', 'workspaces', 'scripts']:
        DIR = os.path.join(os.path.expanduser('~'), '.ar3', folder)
        if not os.path.exists(DIR):
            os.makedirs(DIR)

    logger.status('Downloading module resources from source')
    get_module_resources()

    logger.status("Cloning default config file to ~/.ar3/config.json")
    copyfile('ar3/config.json',LOG_DIR + "/config.json")

    logger.status("Initial setup complete, thank you!")

def first_workspace_check(workspace, logger):
    if not os.path.exists(os.path.join(os.path.expanduser('~'), '.ar3', 'workspaces', workspace)):
        setup_new_workspace(workspace, logger)

def setup_new_workspace(workspace, logger):
    logger.status('Setting up new workspace: {}'.format(workspace))
    db_dir = os.path.join(os.path.expanduser('~'), '.ar3', 'workspaces', workspace)
    dbname = os.path.join(db_dir, 'ar3.db')

    if not os.path.exists(db_dir):
        os.makedirs(db_dir)

    if not os.path.exists(dbname):
        db_obj = Ar3db(workspace, logger)
        db_obj.db_init()
    del db_obj

#!/usr/bin/env python3
# Author: @m8r0wn

import logging
import argparse
from sys import exit, argv
from importlib import import_module

from ar3 import logger
from ar3.first_run import *
from ar3.ops.db.db_core import Ar3db
from ar3.loaders.config_loader import ConfigLoader
from ar3.ops.db.arg_parser import db_args, db_arg_mods
from ar3.ops.enum.arg_parser import enum_args, enum_arg_mods
from ar3.ops.spray.arg_parser import spray_args, spray_arg_mods
from ar3.ops.query.arg_parser import query_args, query_arg_mods
from ar3.ops.shell.arg_parser import shell_args, shell_arg_mods

def banner():
    VERSION = "v1.0.5"
    BANNER = """  

                                   _____                  
         /\        _  ({0})         |  __ \    ({0})            
        /  \   ___| |_ ___   _____| |__) |___ _  __ _ _ __  
       / /\ \ / __| __| \ \ / / _ \  _  // _ \ |/ _` | '_ \ 
      / ____ \ (__| |_| |\ V /  __/ | \ \  __/ | (_| | | | |
     /_/    \_\___|\__|_| \_/ \___|_|  \_\___|_|\__, |_| |_|
                                                 __/ |      
                                                |___/       

             \033[1;33mA network enumeration and attack toolset\033[1;m

                           {1}
    """.format("\033[1;30mX\033[1;m", VERSION)
    return BANNER

def main():
    main_parser = argparse.ArgumentParser(description=banner(), formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
    main_parser._optionals.title = 'Optional Arguments\n\033[1;30m>>-------------------->\033[1;m'
    main_parser.add_argument('-D', '--debug', dest="debug", action='store_true', help='Show debug messages & failed login attempts')
    main_parser.add_argument('-T', dest='max_threads', type=int, default=55, help='Max number of threads to use')
    main_parser.add_argument('--host-max', dest='max_host_threads', type=int, default=20, help='Max threads per host')
    main_parser.add_argument('-W', dest='workspace', type=str, default='', required=False, help='Manually set workspace, otherwise defaults to config file')
    sub_parser = main_parser.add_subparsers(title=' \nOperational Modes\n\033[1;30m>>-------------------->\033[1;m', dest='mode')

    db_args(sub_parser)
    enum_args(sub_parser)
    shell_args(sub_parser)
    spray_args(sub_parser)
    query_args(sub_parser)
    args = main_parser.parse_args()
    if len(argv) <= 2: main_parser.print_help();exit(1)

    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    # Init console logger
    loggers = {}
    loggers['console'] = logger.setup_logger(log_level, 'ar3')

    # First checks & load config
    first_run_check(loggers['console'])
    config_obj = ConfigLoader()
    if not args.workspace:
        setattr(args, 'workspace', config_obj.WORKSPACE)
    first_workspace_check(args.workspace, loggers['console'])

    # Setup file logger
    loggers[args.mode] = logger.setup_file_logger(args.workspace, args.mode)
    # Setup secondary loggers - use argv since arg_mods haven't been made yet
    if '--spider' in argv:
        loggers['spider'] = logger.setup_file_logger(args.workspace, "spider")
    if '--gen-relay-list' in argv:
        loggers['relay_list'] = logger.setup_outfile_logger(args.gen_relay_list, "relay_list")

    # Setup DB
    db_obj = Ar3db(args.workspace, loggers['console'], args.debug)

    try:
        # Start
        args = eval("{}_arg_mods(args, db_obj, loggers)".format(args.mode))
        if args.debug: logger.print_args(args, loggers['console'])

        ops = import_module("ar3.ops.{}".format(args.mode))
        ops.main(args, config_obj, db_obj, loggers)

    except KeyboardInterrupt:
        print("\n[!] Key Event Detected, Closing...")
        exit(0)
    except Exception as e:
        print("[!] ActiveReign Error: {}".format(str(e)))
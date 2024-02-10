import os
import threading
from sys import exit
from time import sleep
from threading import Thread

from ar3.servers.smb import SMBServer
from ar3.ops.enum.spider import spider
from ar3.servers.http import ar3_server
from ar3.ops.enum.host_enum import host_enum
from ar3.helpers.misc import gen_random_string
from ar3.ops.enum.lockout_tracker import LockoutTracker

def requires_smb_server(func):
    def _decorator(options, *args, **kwargs):
        if  options.fileless:
            return func(options, *args, **kwargs)
        return False
    return _decorator


def requires_http_server(func):
    def _decorator(options, *args, **kwargs):
        if options.fileless:
            return func(options, *args, **kwargs)
        return False
    return _decorator


@requires_smb_server
def smb_server_setup(options, logger):
    logger.debug('Starting AR3 SMB Server')
    setattr(options, 'fileless_sharename', '{}$'.format(gen_random_string(7)))
    smb_srv_obj = SMBServer(logger, options.fileless_sharename)
    smb_srv_obj.start()
    return smb_srv_obj


@requires_http_server
def http_server_setup(options, logger):
    logger.debug('Starting AR3 HTTP Server')
    t = Thread(target=ar3_server, args=(logger,))
    t.start()


def thread_launcher(target, args, lockout_obj, config_obj, db_obj, loggers):
    shares = host_enum(target, args, lockout_obj, config_obj, db_obj, loggers)
    if args.spider:
        for share in shares:
            if share not in config_obj.BLACKLIST_SHARE or args.share == share:
                spider(args, config_obj, loggers, db_obj, target, share)


def main(args, config_obj, db_obj, loggers):
    lockout_obj = LockoutTracker(args, loggers)
    servers = { 'smb'  : smb_server_setup(args, loggers['console']),
                'http' : http_server_setup(args, loggers['console'])
              }
    
    active_threads = []
    for target in args.target:
        try:
            t = threading.Thread(target=thread_launcher, args=(target, args, lockout_obj, config_obj, db_obj, loggers,))
            t.daemon = True
            t.start()
            active_threads.append(t)

            while threading.activeCount() > args.max_threads:
                sleep(0.001)

            for t in active_threads:
                if not t.isAlive():
                    active_threads.remove(t)

        except KeyboardInterrupt:
            print("\n[!] Key Event Detected, Closing...")
            exit(0)
        except Exception as e:
            loggers['console'].debug(args.debug, "Enum-Main: {}".format(str(e)))

    # Cleanup & Close
    while len(active_threads) > 0:
        for t in active_threads:
            if not t.isAlive():
                active_threads.remove(t)
        sleep(0.01)

    for server,obj in servers.items():
        if obj:
            obj.cleanup_server()
        os._exit(0)     # Only realy way ive found to shutdown server
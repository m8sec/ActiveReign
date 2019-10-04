import threading
from os import _exit
from time import sleep
from datetime import datetime, timedelta

from ar3.ops.enum.file_parser import ParserThread
from ar3.ops.enum.spider.file_search import SearchThread

def spider(args, config_obj, loggers, db_obj, target, share):
    ''' Launches SearchThread to scan system directories for any file
    outside the config files black list parameters. Then the ParseThread
    is launched to parse files and ID potentially sensitive information'''

    search_thread = SearchThread(args, config_obj, loggers, db_obj, target, share)
    search_thread.daemon = True
    search_thread.start()
    sleep(args.timeout)

    # Launch ParserThread class to discovery data in files
    active_threads = []
    while search_thread.file_queue:
        try:
            d = {}
            d['start_time'] = datetime.now()
            d['thread'] = ParserThread(config_obj, db_obj, args, loggers, search_thread.file_queue[0])
            d['thread'].daemon = True
            d['thread'].start()
            search_thread.file_queue.pop(0)
            active_threads.append(d)

            # Check for thread timeout in search threads and send stop signal
            for th in reversed(active_threads):
                if th['thread'].isAlive() and datetime.now() > th['start_time'] + timedelta(seconds=config_obj.PARSE_TIMEOUT):
                    th['thread'].stop()
                    active_threads.remove(th)

            # Wait while max threads are active or SearchThread is still active
            while threading.activeCount() >= args.max_threads or search_thread.isAlive():
                # break if there are new file to parse
                if search_thread.file_queue and threading.activeCount() < args.max_threads:
                    break
                sleep(0.05)

        except KeyboardInterrupt:
            print("\n[!] Key Event Detected, Closing...")
            _exit(0)

        except Exception as e:
            loggers['console'].debug("\\\\{}\\{}\\\tFile_Search:{}".format(target, share, str(e)))

    # Wait for threads to close and cleanup after each share
    while threading.activeCount() > 2:
        for th in reversed(active_threads):
            if th['thread'].isAlive() and datetime.now() > th['start_time'] + timedelta(seconds=config_obj.PARSE_TIMEOUT):
                th['thread'].stop()
                active_threads.remove(th)
        sleep(0.05)
    del active_threads
    del search_thread
    return
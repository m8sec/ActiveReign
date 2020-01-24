import threading
from ar3.core.smb import SmbCon

class SearchThread(threading.Thread):
    ''' Recursively scan directories, adding
    files to queue to be parsed for data'''

    def __init__(self, args, config, loggers, db, target, share):
        threading.Thread.__init__(self)
        self.file_queue     = []
        self.timeout        = args.timeout
        self.target         = target
        self.share          = share
        self.max_depth      = args.max_depth
        self.start_path     = args.start_path
        self.whitelist_ext  = config.WHITELIST_EXT
        self.blacklist_dir  = config.BLACKLIST_DIR
        self.loggers        = loggers

        self.smbcon = SmbCon(args, loggers, target, db)
        self.smbcon.create_smb_con()

        # Show kickoff messages on startup, if not args.spider startup is called from a module
        if args.spider:
            loggers['console'].info([self.smbcon.host, self.smbcon.ip, "SPIDER", "Scanning \\\\{}\\{}{}".format(target, share, args.start_path.replace("/", "\\"))])
        loggers['spider'].info("Spider\t\\\\{}\\{}{}".format(target, share, args.start_path.replace("/", "\\")))

    def run(self):
        self.recursion(self.start_path)
        self.smbcon.close()
        del self.smbcon

    def recursion(self, path):
        try:
            for x in self.smbcon.list_path(self.share, path+"*"):
                #encoding depending on SMBv1 con or not
                try:
                    filename = x.get_longname().decode('UTF-8')
                except:
                    filename = x.get_longname()

                # Quick fix for gpp passwords on 2019 DC's @TODO create perm fix
                if filename.lower() == "groups":
                    filename = "Groups.xml"

                if filename not in ['.','..']:
                    # If DIR, use recursion to keep searching until max depth hit
                    if x.is_directory() and path.count("/") <= self.max_depth:
                        full_path = path + filename + "/"
                        # Verify not on blacklist
                        if full_path not in self.blacklist_dir:
                            self.loggers['console'].debug("Spider-DIR: {}".format(full_path))
                            self.recursion(full_path)

                    # Check for valid file ext before adding to queue
                    elif filename.split('.')[-1].lower() in self.whitelist_ext:
                        #else add to file queue to be scanned
                        tmp = {
                            'ip'       : self.smbcon.ip,
                            'host'     : self.smbcon.host,
                            'share'    : self.share,
                            'path'     : path,
                            'filename' : filename
                        }
                        self.loggers['console'].debug("Spider-File: {}".format(tmp['filename']))
                        self.file_queue.append(tmp)
                        del tmp
        except:
            pass
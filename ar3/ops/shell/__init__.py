import os
from ar3.core.smb import SmbCon
from ar3.servers.smb import SMBServer
from ar3.core.connector import Connector
from ar3.helpers.misc import gen_random_string
from ar3.ops.enum.host_enum import code_execution

class AR3Shell(Connector):
    def __init__(self, args, db_obj, config_obj, loggers):
        Connector.__init__(self, args, loggers, args.target)
        self.output     = []
        self.pwd_list   = ['C:', 'Windows', 'System32']
        self.pwd        = '\\'.join(self.pwd_list)

        self.exec_method  = args.exec_method
        self.sharename    = args.fileless_sharename
        self.db           = db_obj
        self.config_obj   = config_obj


        try:
            # Setup Smb Connection
            self.logger.status('Initiating remote connection')
            self.smbcon = SmbCon(self.args, loggers, self.host, self.db)
            self.smbcon.create_smb_con()

            # Execute command to verify permissions
            self.cmd_execution('ECHO %USERDOMAIN%\%USERNAME%')
            self.logger.success('Starting emulated shell (Host: {}) (User: {}) (Method: {}) (Fileless: {})'.format(self.host, self.output[0].strip(), self.exec_method, str(args.fileless)))
            self.logger.warning("This is a limited shell and requires full paths for file interactions\n")

        except Exception as e:
            self.logger.fail("Error Starting Shell: {}".format(str(e)))
            exit(1)

    def help(self):
        print("""
          help                                    - show this menu
          exit                                    - Close shell
        
        Navigation:
          pwd                                   - Show PWD
          dir                                   - List PWD
          cd                                    - Change directory
          
        File Interactions:
          type [remote_file]                    - Show file contents    (Full Path Required)
          download [remote_file] [location]     - Download remote file  (Full Path Required)
          upload [local_file] [location]        - Upload local file     (Full Path Required)
          delete [remote_file]                  - Delete remote file    (Full Path Required)
          
        Commands:
          [cmd]                                 - Execute remote cmd
        """)

    def cd(self, cmd):
        if cmd.startswith('cd'):
            try:
                cd_path = cmd.split(' ')[1]
                cd_split = cd_path.replace("\\", "/").split("/") # Input formatting
                cd_split = [x for x in cd_split if x]            # Remove blanks

                if cd_path == "/" or cd_path == "\\":
                    self.pwd_list = ['C:']

                # Dir up
                elif cd_split[0] == "..":
                    self.pwd_list.pop(-1)
                    cd_split.pop(cd_split.index(".."))

                # new dir
                elif cd_path.startswith(("/", "\\")):
                    self.pwd_list = ['C:']

                self.pwd_list = self.pwd_list + cd_split

            except:
                self.logger.FAIL('Unable to change directories')

    def dir(self, cmd):
        if cmd == "dir":
            return self.cmd_execution("dir {}".format(self.pwd))
        else:
            return self.cmd_execution(cmd)

    def download(self, cmd):
        try:
            val = cmd.split(" ")
            self.smbcon.downloadFile(val[1], val[2])
            self.logger.success("Download Complete: {}".format(val[2]))
        except Exception as e:
            if str(e) == "list index out of range":
                self.logger.fail('Not enough values to unpack, see -h for more')
            else:
                self.logger.fail("Download Failed: {}".format(str(e)))

    def upload(self, cmd):
        try:
            val = cmd.split(" ")
            self.smbcon.uploadFile(val[1], val[2])
            self.logger.success("Upload Complete: {}".format(val[2]))
        except Exception as e:
            if str(e) == "list index out of range":
                self.logger.fail('Not enough values to unpack, see -h for more')
            else:
                self.logger.fail("Upload Failed: {}".format(str(e)))

    def delete(self, cmd):
        try:
            val = cmd.split(" ")
            self.smbcon.deleteFile(val[1])
            self.logger.success("Download Complete: {}".format(val[1]))
        except Exception as e:
            if str(e) == "list index out of range":
                self.logger.fail('Not enough values to unpack, see -h for more')
            else:
                self.logger.fail("Deletion Failed: {}".format(str(e)))

    def cmd_execution(self, cmd):
        resp = code_execution(self.smbcon, self.args, self.host, self.loggers, self.config_obj, cmd, return_data=True)
        self.output = resp.splitlines()

    def cmdloop(self):
        while True:
            try:
                # init prompt
                self.output = []
                self.pwd = '\\'.join(self.pwd_list)
                cmd = input("{}> ".format(self.pwd))
                cmd = cmd.lstrip().rstrip()

                self.logger.debug("User cmd ::: \'{}\'".format(cmd))

                # Handle CMD input
                if cmd == "help":
                    self.help()

                elif cmd == 'exit':
                    try:
                        self.smbcon.close()
                    except:
                        pass
                    return True

                elif cmd.startswith('cd'):
                    self.cd(cmd)

                elif cmd.startswith('dir'):
                    self.dir(cmd)

                elif cmd.startswith('download'):
                    self.download(cmd)

                elif cmd.startswith('upload'):
                    self.upload(cmd)

                elif cmd.startswith('delete'):
                    self.delete(cmd)

                elif cmd == 'pwd':
                    self.logger.output(self.pwd)

                else:
                    self.output = self.cmd_execution(cmd)

                # Show cmd Output
                for result in self.output:
                    self.logger.output(result)

            except KeyboardInterrupt:
                try:
                    self.smbcon.close()
                except:
                    pass
                return True
            except Exception as e:
                self.logger.debug(str(e))

def main(args, config_obj, db_obj, loggers):
    shell = None
    smb_srv_obj = None
    try:
        # Init smb server
        if args.fileless:
            # Start smbserver
            setattr(args, 'fileless_sharename', 'TEMP-{}$'.format(gen_random_string()))
            smb_srv_obj = SMBServer(loggers['console'], args.fileless_sharename, verbose=args.debug)
            smb_srv_obj.start()

        # Enter CMD Loop
        shell = AR3Shell(args, db_obj, config_obj, loggers)
        shell.cmdloop()

        # Close smbserver & exit
        if args.fileless:
            smb_srv_obj.cleanup_server()
            smb_srv_obj.server = None
            os._exit(0)
    except KeyboardInterrupt:
        # Cleanup and close
        if shell:
            shell.smbcon.close()
        if smb_srv_obj:
            smb_srv_obj.cleanup_server()
        return
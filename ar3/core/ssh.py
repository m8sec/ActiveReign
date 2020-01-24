import socket
import paramiko
from paramiko.ssh_exception import AuthenticationException, NoValidConnectionsError, SSHException
from ar3.core.connector import Connector

class SSH():
    def __init__(self,args, loggers, host, db):
        Connector.__init__(self, args, loggers, host)
        self.admin   = False
        self.port    = 22
        self.key     = False
        self.signing = 'N/A'
        self.smbv1   = 'N/A'
        self.auth    = False

    def ssh_connection(self):
        try:
            self.con = paramiko.SSHClient()
            self.con.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.con.connect(self.host, port=self.port, timeout=2)
        except AuthenticationException:
            return True
        except SSHException:
            return True
        except NoValidConnectionsError:
            return False
        except socket.error:
            return False
        except:
            return False

    def login(self):
        if self.username:
            if self.key:
                self.auth_key()
            else:
                self.auth_password()
            if self.auth:
                self.isAdmin()

    def auth_password(self):
        try:
            self.con.connect(self.ip, port=self.port, username=self.username, password=self.password)
            self.auth = True
            return True
        except Exception as e:
            return False

    def auth_key(self):
        try:
            paramiko.RSAKey.from_private_key_file(self.key)
            self.con.connect(hostname=self.ip, port=self.port, username=self.username, key_filename=self.key, timeout=self.timeout)
            self.auth = True
            return True
        except:
            return False

    def host_info(self):
        try:
            self.version = self.con.get_transport().remote_version.strip()
            if not self.version:
                self.version = 'No Banner'
        except:
            self.version = "SSH Banner Failed"

    def execute(self, command):
        self.__outputBuffer = ''
        stdin, stdout, stderr = self.con.exec_command(command)
        stdin.flush()
        for line in stdout.readlines():
            self.__outputBuffer += line.strip()
        return self.__outputBuffer


    def isAdmin(self):
        try:
            stdin, stdout, stderr = self.con.exec_command('echo $EUID')
            stdin.flush()
            output = stdout.read().decode('utf-8').strip()
            if output == '0':
                self.admin = True
        except:
            self.admin = False

    def close(self):
        self.con.close()
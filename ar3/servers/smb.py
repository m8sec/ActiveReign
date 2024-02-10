'''
Help From:
https://github.com/byt3bl33d3r/CrackMapExec/blob/master/cme/servers/smb.py
https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py
'''

import os
import shutil
import threading
from sys import exit
from impacket import smbserver
from impacket.ntlm import compute_lmhash, compute_nthash

class SMBServer(threading.Thread):
    def __init__(self, logger, share_name, share_path='/tmp/.ar3', share_comment = '', username= '', password='', listen_address='0.0.0.0', listen_port=445, verbose=False):
        self.running = True
        self._smb2support = False
        self._share_path = share_path

        try:
            threading.Thread.__init__(self)

            # If suggested share_path not exist, create
            if not os.path.exists(share_path):
                os.makedirs(share_path)

            # Setup SMB Server
            self.server = smbserver.SimpleSMBServer(listen_address, int(listen_port))
            self.server.addShare(share_name, share_path, share_comment)
            if verbose:
                self.server.setLogFile('')
            self.server.setSMB2Support(self._smb2support)
            self.server.setSMBChallenge('')

            if username:
                if password:
                    lmhash = compute_lmhash(password)
                    nthash = compute_nthash(password)
                self.server.addCredential(username, 0, lmhash, nthash)

        except Exception as e:
            errno, message = e.args
            if errno == 98 and message == 'Address already in use':
                logger.fail('Error starting SMB server on port 445: the port is already in use')
            else:
                logger.fail('Error starting SMB server on port 445: {}'.format(message))
                exit(1)

    def addShare(self, share_name, share_path, share_comment):
        self.server.addShare(share_name.upper(), share_path, share_comment)

    def run(self):
        try:
            self.server.start()
        except Exception as e:
            pass

    def cleanup_server(self):
        try:
            shutil.rmtree(self._share_path)
        except:
            pass

    def shutdown(self):
        '''Not in use, only way I found
        to shutdown server was _exit()'''

        self.cleanup_server()
        self._Thread__stop()
        # make sure all the threads are killed
        for thread in threading.enumerate():
            if thread.isAlive():
                try:
                    thread._Thread__stop()
                except Exception as e:
                    self.logger.debug(str(e))

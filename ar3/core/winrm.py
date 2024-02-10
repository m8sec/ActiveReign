# Modified from:
#   https://github.com/byt3bl33d3r/CrackMapExec/blob/master/cme/protocols/winrm.py

import winrm
import requests

class WINRM():
    def __init__(self, logger, host, args, smb_con, share_name=False):
        if share_name:
            raise Exception('WINRM does not support fileless execution')
        self.args    = args
        self.host    = host
        self.smb_con = smb_con
        self.logger  = logger

        try:
            if not self.winrm_con() and args.module != 'test_execution':
                self.logger.fail([self.smb_con.host, self.smb_con.ip, "WINRM", "No WINRM endpoint detected"])
            self.winrm_login()
        except Exception as e:
            raise Exception("WINRM Error: {}".format(str(e)))

    def winrm_con(self):
        endpoints = [
            'https://{}:5986/wsman'.format(self.host),
            'http://{}:5985/wsman'.format(self.host)]
        for url in endpoints:
            try:
                requests.get(url, verify=False, timeout= self.args.timeout)
                self.endpoint = url
                self.logger.debug([self.smb_con.host, self.smb_con.ip, "WINRM", "Endpoint found: {}".format(self.endpoint)])
                return True
            except:
                pass
        return False

    def winrm_login(self):
        self.con = winrm.Session(self.endpoint,
                                    auth=('{}\\{}'.format(self.args.domain, self.args.user), self.args.passwd),
                                    transport='ntlm',
                                    server_cert_validation='ignore')

    def execute(self, command):
        try:
            if self.args.ps_execute:
                r = self.con.run_ps(command)
            else:
                r = self.con.run_cmd(command)
            return self.parse_output(r)
        except Exception as e:
            return str(e)

    def parse_output(self, response_obj):
        if response_obj.status_code == 0:
            return response_obj.std_out.decode('UTF-8')
        else:
            return response_obj.decode('UTF-8')
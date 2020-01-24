from threading import Thread
from ar3.core.winrm import WINRM
from ar3.core.wmiexec import WMIEXEC
from ar3.core.smbexec import SMBEXEC
from ar3.core.atexec import TSCHEXEC
from ar3.servers.smb import SMBServer
from ar3.helpers.misc import gen_random_string

class TestExecution():
    def __init__(self):
        self.name           = 'test_execution'
        self.description = 'Use on single system with known admin privileges to determine optimal execution method'
        self.author         = ['@m8r0wn']
        self.requires_admin = True
        self.exec_methods   = ['wmiexec', 'smbexec', 'atexec', 'winrm']
        self.args           = {}

    def test_execution(self, args, smb_con, target, exec_method, exec_type, logger):
        test_string = gen_random_string()
        try:
            executioner = exec_method(logger, target, args, smb_con, share_name=self.exec_type[exec_type])
            cmd_result = executioner.execute('echo {}').format(test_string).splitlines()[0]

            if test_string == cmd_result.strip():
                self.exec_method[exec_method][exec_type] = '\033[1;32mSUCCESS\033[0m'
        except:
            return


    def run(self, target, args, smb_con, loggers, config_obj):
        logger = loggers['console']
        # Log Results
        self.exec_method = {
            WMIEXEC  : {'Name'      : 'WMIEXEC',
                        'Fileless'  : '\033[1;31mFAILED\033[0m',
                        'Remote'    : '\033[1;31mFAILED\033[0m'
                        },

            SMBEXEC  : {'Name'      : 'SMBEXEC',
                        'Fileless'  : '\033[1;31mFAILED\033[0m',
                        'Remote'    : '\033[1;31mFAILED\033[0m'
                        },
            TSCHEXEC:   {'Name': 'ATEXEC',
                        'Fileless': '\033[1;31mFAILED\033[0m',
                        'Remote': '\033[1;31mFAILED\033[0m'
                       },
            WINRM   :  {'Name'      : 'WINRM',
                        'Fileless'  : '\033[1;33mN/A\033[0m',
                        'Remote'    : '\033[1;31mFAILED\033[0m'
                       }
                    }
        # Define remote/fileless via share
        self.exec_type = {
            'Remote'     : '',
            'Fileless'  : gen_random_string()
                    }

        # Verify Admin
        if not smb_con.admin:
            logger.warning("{} Error: This module can only be run on a system with admin permissions".format(self.name))
            return

        # Start smbserver
        smb_srv_obj = SMBServer(loggers['console'], self.exec_type['Fileless'], verbose=args.debug)
        smb_srv_obj.start()

        logger.info([smb_con.host, smb_con.ip, self.name.upper(), 'Testing execution methods'])
        # Test execution method using threading for timeouts
        try:
            for exec_method in self.exec_method:
                for exec_type in self.exec_type:
                    t = Thread(target=self.test_execution, args=(args, smb_con, target, exec_method, exec_type, logger))
                    t.start()
                    t.join(args.timeout+3)
        except Exception as e:
            logger.debug("{} Error: {}".format(self.name, str(e)))

        # Print Results
        for xmethod, data in self.exec_method.items():
            logger.info([smb_con.host, smb_con.ip, self.name.upper(), '\033[1;30mExecution Method:\033[0m {:<10} \033[1;30mFileless: {:<20} \033[1;30mRemote (Defualt): {}'.format(data['Name'], data['Fileless'], data['Remote'])])

        # Shutdown SMBServer and Exit
        smb_srv_obj.cleanup_server()
        smb_srv_obj.server = None
        return

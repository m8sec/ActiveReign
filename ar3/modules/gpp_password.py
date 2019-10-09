from ar3.ops.enum.spider import spider
from ar3.logger import setup_file_logger


class GPP_Password():
    def __init__(self):
        self.name           = 'gpp_password'
        self.description    = 'Looks for "cpassword" values in SYSVOL'
        self.author         = ['@m8r0wn']
        self.requires_admin = False
        self.args = {
            'DC': {
                'Description'   : 'Domain Controller (otherwise provided target will be used)',
                'Required'      : False,
                'Value'         : ''
            }
        }

    def run(self, target, args, smb_con, loggers, config_obj):
        # Define Target
        self.count = 0
        if self.args['DC']['Value']:
            target = self.args['DC']['Value']

        # Create custom spider config
        temp_config = config_obj
        temp_config.WHITELIST_EXT = ['xml']
        temp_config.KEY_EXT       = []
        temp_config.KEY_WORDS     = []
        temp_config.REGEX         = {"gpp_password": "^.*cpassword=.*$"}

        # Override args
        setattr(args, 'max_depth', 12)
        setattr(args, 'spider', False)

        # Create spider logger
        loggers['spider'] = setup_file_logger(args.workspace, "spider")

        # Start
        loggers['console'].info([smb_con.host, smb_con.ip, "GPP_PASSWORD", "Searching \\\\{}\\SYSVOL\\".format(target)])
        spider(args, temp_config, loggers, smb_con.db, target, 'SYSVOL')
        loggers['console'].info([smb_con.host, smb_con.ip, self.name.upper(), "Module complete"])

def cpassword_parser(loggers, host, ip, filename, data):
    loggers['console'].success([host, ip, "GPP_PASSWORD", "{:<9} : {}".format("File", filename)])
    for line in data.split(' '):
        if line.startswith(("userName", "newName", "password", "changed", "cpassword")):
            try:
                tmp = line.split('=')
                param = tmp[0]
                value = tmp[1].strip('\"')
                if param == 'cpassword':
                    value = cpassword_decrypt(value)
                loggers['console'].success([host, ip, "GPP_PASSWORD", "{:<9} : {}".format(param.title(), value)])
            except:
                pass

def cpassword_decrypt(cpassword):
    """
    Sorry no decryption available yet, workin' on it </3
    """
    try:
        return cpassword
    except:
        return cpassword


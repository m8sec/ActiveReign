from ar3.core.wmi import WmiCon
from ar3.logger import highlight

class InvertHunter():
    def __init__(self):
        self.name           = 'invert_hunter'
        self.description    = 'Search system(s) for the absence of a process (i.e: AV_product.exe)'
        self.author         = ['@m8r0wn']
        self.requires_admin = True
        self.args = {
            'PROCESS': {
                'Description'   : 'Process to search for',
                'Required'      : True,
                'Value'         : ''
            }
        }

    def run(self, target, args, smb_con, loggers, config_obj):
        logger = loggers['console']
        proc_found = False
        x = WmiCon(args, loggers, smb_con.ip, smb_con.host)
        try:
            x.get_netprocess()
        except Exception as e:
            logger.debug("{} Error: {}".format(self.name, str(e)))

        logger.debug("{}: Identified {} processes running on {}".format(self.name, str(len(x.process_list.keys())), target))
        logger.debug("Searching for absence of: {}".format(self.args['PROCESS']['Value']))

        for pid, data in x.process_list.items():
            if self.args['PROCESS']['Value'].lower() == data['processname'].lower():
                logger.fail([smb_con.host, smb_con.ip, self.name.upper(), "PID: {:<6} Name: {:<20} User: {:<17} Host: {:<25} Domain: {}".format(pid, data['processname'], data['user'], data['computername'], data['domain'])])
                return
        logger.success([smb_con.host, smb_con.ip, self.name.upper(), "{} NOT found on {}".format(self.args['PROCESS']['Value'], smb_con.host)])



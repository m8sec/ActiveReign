from ar3.core.rpc import RpcCon

class UserHunter():
    def __init__(self):
        self.name = 'user_hunter'
        self.description = 'Search for specific user with active session on system'
        self.author = ['@m8r0wn']
        self.args = {
            'USER': {
                'Description'   : 'User to search for',
                'Required'      : True,
                'Value'         : ''
            }
        }

    def run(self, target, args, smb_con, loggers, config_obj):
        logger = loggers['console']
        x = RpcCon(args, loggers, target)
        try:
            x.get_netsessions()
        except Exception as e:
            logger.debug("{} Error: {}".format(self.name, str(e)))

        logger.debug("{}: Identified {} active sessions on {}".format(self.name, str(len(x.sessions.keys())), target))
        for user, data in x.sessions.items():
            if self.args['USER']['Value'].lower() == data['user'].lower():
                logger.success([smb_con.host, smb_con.ip, self.name.upper(), "{:<15} User: {}".format(data['host'], user)])

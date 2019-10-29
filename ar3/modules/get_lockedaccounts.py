from ar3.core.ldap import LdapCon

class GetLockedAccounts():
    def __init__(self):


        self.name           = 'lockedaccounts'
        self.description    = 'List active domain accounts that are locked or within 1 away from the threshold'
        self.author         = ['@m8r0wn']
        self.requires_admin = False
        self.args = {
            'THRESHOLD': {
                'Description': 'Lockout threshold if LDAP fails (Default: 3)',
                'Required'   : False,
                'Value'      : 3
            },
            'SERVER': {
                'Description': 'Define LDAP Server',
                'Required'   : False,
                'Value'      : ''
            }
        }


    def run(self, target, args, smb_con, loggers, config_obj):
        logger = loggers['console']
        users = {}
        domain = {}

        try:
            # Create LDAP Con
            x = LdapCon(args, loggers, args.ldap_srv, smb_con.db)
            x.create_ldap_con()
            if not x:
                logger.fail([smb_con.host, smb_con.ip, self.name.upper(), 'Unable to create LDAP connection'])
                return
            logger.success([smb_con.host, smb_con.ip, self.name.upper(), 'Connection established  (server: {}) (LDAPS: {})'.format(x.host, x.ldaps)])

            # Get Domain Lockout Threshold
            domain = x.domain_query(False)
            try:
                lockout_threshold = int(domain[list(domain.keys())[0]]['lockoutThreshold'])
                logger.info([smb_con.host, smb_con.ip, self.name.upper(), "Domain Lockout Threshold Detected: {}".format(lockout_threshold), "Logon_Server: {}".format(x.host)])

            except:
                lockout_threshold = self.args['Lockout']['Value']
                logger.info([smb_con.host, smb_con.ip, self.name.upper(), "Lockout threshold detection failed, using default: {}".format(lockout_threshold)])

            #Collect users
            users = x.user_query('active', False)
            logger.debug("{}: Identified {} domain users".format(self.name, str(len(users.keys())),))
            if users:
                # Compare
                for user, data in users.items():
                    try:
                        if int(data['badPwdCount']) >= lockout_threshold:
                            logger.success([smb_con.host, smb_con.ip, self.name.upper(), user,"BadPwd: \033[1;31m{:<5}\033[1;m".format(data['badPwdCount']),"Logon_Server: {}".format(x.host)])

                        elif int(data['badPwdCount']) >= (lockout_threshold-1):
                            logger.success([smb_con.host, smb_con.ip, self.name.upper(), user, "BadPwd: \033[1;33m{:<5}\033[1;m".format(data['badPwdCount']), "Logon_Server: {}".format(x.host)])
                    except:
                        pass
            else:
               logger.fail("{}: No users returned from query".format(self.name))
            x.close()
        except Exception as e:
            logger.debug("{} Error: {}".format(self.name, str(e)))

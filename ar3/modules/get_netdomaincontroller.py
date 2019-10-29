from ar3.core.ldap import LdapCon
from ar3.core.ldap.query import ATTRIBUTES

class GetNetDomainController():
    def __init__(self):
        self.name           = 'domaincontroller'
        self.description    = 'List domain controllers on domain'
        self.author         = ['@m8r0wn']
        self.requires_admin = False
        self.args           = {}

    def run(self, target, args, smb_con, loggers, config_obj):
        logger = loggers['console']
        x = LdapCon(args, loggers, args.ldap_srv, smb_con.db)
        try:
            x.create_ldap_con()
            dc_data = x.custom_query('(userAccountControl:1.2.840.113556.1.4.803:=8192)', ATTRIBUTES['cpu'])
            x.close()
        except Exception as e:
            logger.debug("{} Error: {}".format(self.name, str(e)))

        if x.data:
            for srv, data in dc_data.items():
                logger.success([smb_con.host, smb_con.ip, self.name.upper(), "{:<20} OS: {}".format(srv, data['operatingSystem'])])
        else:
            logger.fail([smb_con.host, smb_con.ip, self.name.upper(), "No data returned".format(self.name)])
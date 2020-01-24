from dns.resolver import Resolver

from ar3.core.ldap import LdapCon
from ar3.core.ldap.query import QUERIES, ATTRIBUTES, UAC_LOOKUP


def resolve_host(host, dns_server):
    # Reuses ldap_srv value to resolve dns names (Assumes this is a DC)
    try:
        res = Resolver()
        res.timeout = 3
        res.lifetime = 3
        res.nameservers = [dns_server]
        dns_query = res.query(host, "A")
        for ip in dns_query:
            return ip
    except KeyboardInterrupt:
        exit(0)
    except:
        pass
    return ''

def attribute_parser(logger, host, ip, key, attribute, data, title="PARSER"):
    KEYWORDS = ['password', 'key', 'login', 'logon', 'pass']
    for k in KEYWORDS:
        if k in data.lower():
            logger.success([host, ip, title.upper(), '{:<10} Attribute: {:<15} Value: \"{}\"'.format(key, attribute, data)])

#########################
# USERS
#########################
def user_query(args, query, loggers, db_obj, user_lookup=False):
    resp = query.user_query(user_lookup, args.attrs, all_users=args.all)
    for key, data in resp.items():
        try:
            data['sAMAccountName'] = data['sAMAccountName'].replace("\'", '')
            db_obj.update_username(args.domain, data['sAMAccountName'])
            user_handler(args, loggers['console'], query.host, query.ip, data['sAMAccountName'], data)
        except Exception as e:
            loggers['console'].warning(["Query Error {}".format(key), str(e)])

def user_handler(args, logger, host, ip, user, data):
    if args.data_only:
        logger.output(user)
        return

    for attribute, value in data.items():
        if args.parse and attribute.lower() in ['info','comment','description']:
            attribute_parser(logger, host, ip, user, attribute, value)

        # UserAccountControl Lookup
        if attribute == 'userAccountControl':
            if value in UAC_LOOKUP.keys():
                value = "{} ({})".format(UAC_LOOKUP[value], value)

        if (args.verbose) or (args.query):
            logger.info([host, ip, "USERS", "{:<20} {:<24} : {}".format(user, attribute, value)])
        else:
            logger.info([host, ip, "USERS", user])
            return

#########################
# GROUPS
#########################
def group_query_all(args, query, loggers, db_obj):
    # Enumerate all groups and users on the domain
    for group in query.con.group_query([]).keys():
        group_query(args, query.con, loggers, db_obj, group_lookup=group)

def group_query(args, query, loggers, db_obj, group_lookup=False):
    # Enum groups or lookup members of a single group
    if group_lookup:
        resp = query.group_membership(group_lookup, args.attrs)
        if resp:
            db_obj.update_group(group_lookup, args.domain)
        for key, data in resp.items():
            key = key.replace("\'", '')
            try:
                if 'userAccountControl' in data.keys():
                    db_obj.update_username(args.domain, key)
                    db_obj.update_user_members(args.domain, key, group_lookup)
                    group_membership_handler(args, loggers['console'], query.host, query.ip, key, data, group_lookup)
                else:
                    db_obj.update_group(key, args.domain)
                    db_obj.update_group_members(args.domain, key, group_lookup)
                    group_membership_handler(args, loggers['console'], query.host, query.ip, key, data, group_lookup, title='MEMBER: GROUP')
            except Exception as e:
                loggers['console'].warning(["Query Error {}".format(key), str(e)])

    else:
        resp = query.group_query(args.attrs)
        for key, data in resp.items():
            try:
                key = key.replace("\'", '')
                db_obj.update_group(key, args.domain)
                group_handler(args, loggers['console'], query.host, query.ip, key, data)
            except Exception as e:
                loggers['console'].warning(["Query Error {}".format(key), str(e)])

def group_handler(args, logger, host, ip, key, data):
    if args.data_only:
        logger.output(key)
        return

    for attribute, value in data.items():
        if args.parse and attribute.lower() in ['info', 'comment', 'description']:
            attribute_parser(logger, host, ip, key, attribute, value)

        if args.verbose:
            logger.info([host, ip, "GROUPS", "{:<40} {:<25} : {}".format(key, attribute, value)])
        else:
            try:
                logger.info([host, ip, "GROUPS", key, data['description']])
            except:
                logger.info([host, ip, "GROUPS", key])
            return

def group_membership_handler(args, logger, host, ip, user, data, group, title='MEMBER: USER'):
    if args.data_only:
        logger.output(user)
        return

    for attribute, value in data.items():
        if args.parse and attribute.lower() in ['info', 'comment', 'description']:
            attribute_parser(logger, host, ip, user, attribute, value)

        if args.verbose:
            logger.info([host, ip, title, "{:<40} {:<25} {:<20} : {}".format(group, user, attribute, value)])
        else:
            logger.info([host, ip, title, "{:<40} {}".format(group, user)])
            return

#########################
# COMPUTERS
#########################
def computer_query(args, query, loggers, db_obj):
    resp = query.computer_query(args.query, args.attrs)
    for key, data in resp.items():
        try:
            computer_handler(args, loggers['console'], query.host, query.ip, key, data, db_obj)
        except Exception as e:
            loggers['console'].warning(["Query Error {}".format(key), str(e)])

def computer_handler(args, logger, host, ip, key, data, db_obj):
    if args.data_only:
        logger.output(key)
        return

    resolve = resolve_host(key, ip)
    try:
        db_obj.update_host_ldap(key, resolve, args.domain, data['operatingSystem'])
    except:
        db_obj.update_host_ldap(key, resolve, args.domain, '')

    for attribute, value in data.items():
        if args.parse and attribute.lower() in ['info','comment','description']:
            attribute_parser(logger, host, ip, key, attribute, value)

        if args.verbose:
            logger.info([host, ip, "COMPUTERS", "{:<35} {:<24} : {:<40} {}".format(key, attribute, value, resolve)])
        elif args.query == 'eol':
            logger.info([host, ip, "COMPUTERS","{:<35} {} {:<40} {}".format(key, data['operatingSystem'],data['operatingSystemServicePack'], resolve)])
            return
        else:
            logger.info([host, ip, "COMPUTERS", key, resolve])
            return

#########################
# DOMAIN
#########################
def domain_query(args, query, loggers, db_obj):
    resp = query.domain_query(args.attrs)
    for key, data in resp.items():
        domain_handler(args, loggers['console'], query.host, query.ip, key, data, db_obj)

def domain_handler(args, logger, host, ip, key, data, db_obj):
    if args.data_only:
        logger.output(key)
        return
    try:
        db_obj.update_domain_ldap(args.domain, data['lockoutThreshold'], data['lockoutDuration'], data['minPwdLength'], data['maxPwdAge'])
    except:
        db_obj.update_domain(args.domain, data['lockoutThreshold'])

    for attribute, value in data.items():
        logger.info([host, ip, "DOMAIN", "{:<20} {:<24} : {}".format(key, attribute, value)])

#########################
# TRUSTS
#########################
def trust_query(args, query, loggers, db_obj):
    resp = query.trust_query(args.attrs)
    for key, data in resp.items():
        trust_handler(args, loggers['console'], query.host, query.ip, key, data)

def trust_handler(args, logger, host, ip, key, data):
    if args.data_only:
        logger.output(key)
        return

    for attribute, value in data.items():
        logger.info([host, ip, "TRUST", "{:<20} {:<24} : {}".format(key, attribute, value)])

#########################
# CUSTOM
#########################
def custom_query(args, cust_query, cust_attr, query_obj, loggers, db_obj, title='CUSTOM'):
    resp = query_obj.custom_query(cust_query, cust_attr)
    for key, data in resp.items():
        custom_handler(args, loggers['console'], query_obj.host, query_obj.ip, key, data, title)

def custom_handler(args, logger, host, ip, key, data, title):
    if args.data_only:
        logger.output(key)
        return

    for attribute, value in data.items():
        if args.parse and attribute.lower() in ['info','comment','description']:
            attribute_parser(logger, host, ip, key, attribute, value)

        if args.verbose:
            logger.info([host, ip, title.upper(), "{:<35} {:<24} : {}".format(key, attribute, value)])
        else:
            logger.info([host, ip, title.upper(), key])
            return

def create_con(args, loggers, db_obj):
    query = LdapCon(args, loggers, args.ldap_srv, db_obj)
    query.create_ldap_con()

#########################
# Recon
#########################
def recon(args, query, loggers, db_obj):
    """
    Reconnection to avoid timeout
    """
    query.create_ldap_con()
    domain_query(args, query.con, loggers, db_obj)
    query.close()

    query.create_ldap_con()
    user_query(args, query.con, loggers, db_obj, user_lookup="{active}")
    query.close()

    query.create_ldap_con()
    group_query_all(args, query, loggers, db_obj)
    query.close()

    query.create_ldap_con()
    computer_query(args, query.con, loggers, db_obj)

#########################
# Connection
#########################
class LDAPHandler():
    """
    Small class to handle ldap connection. Otherwise we receive a timeout
    error when attempting multiple queries on the same connection.
    """
    def __init__(self, args, loggers, db_obj):
        self.con     = False
        self.count   = 0
        self.args    = args
        self.loggers = loggers
        self.db      = db_obj

    def create_ldap_con(self):
        try:
            if self.con:
                self.con.close()

            self.con = LdapCon(self.args, self.loggers, self.args.ldap_srv, self.db)
            self.con.create_ldap_con()

            self.count += 1
            if self.count == 1:
                # Output formatting indicating a successful connection
                self.loggers['console'].success(['LDAP Connection','Connection established (server: {}) (LDAPS: {})'.format(self.con.host,self.con.ldaps)])
        except Exception as e:
            raise Exception(e)

    def close(self):
        if self.con:
            self.con.close()

#########################
# Main
#########################
def main(args, config_obj, db_obj, loggers):
    try:
        query = LDAPHandler(args, loggers, db_obj)

        if args.recon:
            recon(args, query, loggers, db_obj)

        if args.qdomain:
            query.create_ldap_con()
            domain_query(args, query.con, loggers, db_obj)

        if args.trust:
            query.create_ldap_con()
            trust_query(args, query.con, loggers, db_obj)

        if args.users:
            query.create_ldap_con()
            user_query(args, query.con, loggers, db_obj, user_lookup=args.query)

        if args.groups:
            query.create_ldap_con()
            if args.all:
                group_query_all(args, query, loggers, db_obj)
            else:
                group_query(args, query.con, loggers, db_obj, group_lookup=args.query)

        if args.computers:
            query.create_ldap_con()
            computer_query(args, query.con, loggers, db_obj)

        if args.pass_never_expire:
            query.create_ldap_con()
            custom_query(args, QUERIES['pass_never_expire'], ATTRIBUTES['users'] + args.attrs, query.con, loggers, db_obj, title="PASS NEVER EXPIRE  ")

        if args.pass_not_required:
            query.create_ldap_con()
            custom_query(args, QUERIES['pass_not_required'], ATTRIBUTES['users'] + args.attrs, query.con, loggers, db_obj, title="PASS NOT REQUIRED  ")

        if args.reversible_encryption:
            query.create_ldap_con()
            custom_query(args, QUERIES['reversible_encryption'], ATTRIBUTES['users'], query.con, loggers, db_obj, title="REVERSIBLE ENCRYPTION  ")

        if args.custom:
            query.create_ldap_con()
            custom_query(args, args.custom, args.attrs, query.con, loggers, db_obj)

        query.close()
    except Exception as e:
        if "invalidCredentials" in str(e):
            loggers['console'].fail(["LDAP Error", "Authentication failed"])
        else:
            loggers['console'].fail(["Query Error", str(e)])
from impacket.ldap import ldap
from ar3.core.connector import Connector
from ar3.core.ldap.query import QUERIES, ATTRIBUTES

class LdapCon(Connector):
    def __init__(self, args, loggers, host, db):
        Connector.__init__(self, args, loggers, host)
        self.ldaps = False
        self.con   = None
        self.data  = {}
        self.set_baseDN()
        self.db = db
    ##################################################
    # Ldap Connection & Authentication
    ##################################################
    def create_ldap_con(self):
        if self.ldap_connection():
            try:
                self.con._socket.settimeout(self.timeout)
                self.con.login(self.username, self.password, self.domain, lmhash=self.lmhash, nthash=self.nthash)
                self.db.update_user(self.username, self.password, self.domain, self.hash)
            except Exception as e:
                raise Exception(str(e))
        else:
            raise Exception('Connection to server failed')

    def ldap_connection(self,):
        if self.ldap_con():
            return True
        elif self.ldaps_con():
            return True
        return False

    def ldap_con(self):
        try:
            self.con = ldap.LDAPConnection("ldap://{}".format(self.ip))
            return True
        except:
            return False

    def ldaps_con(self):
        try:
            self.con = ldap.LDAPConnection("ldaps://{}".format(self.ip))
            self.ldaps = True
            return True
        except:
            return False

    ##################################################
    # Ldap Query Functions
    ##################################################
    def set_baseDN(self):
        self.baseDN = ''
        # Set domain name for baseDN
        try:
            for x in self.domain.split('.'):
                self.baseDN += 'dc={},'.format(x)

            # Remove last ','
            self.baseDN = self.baseDN[:-1]
        except:
            self.baseDN = 'dc={}'.format(self.domain)

    def execute_query(self, searchFilter, attrs, parser):
        sc = ldap.SimplePagedResultsControl(size=9999)
        try:
            self.con.search(searchBase=self.baseDN, searchFilter=searchFilter, attributes=attrs, searchControls=[sc], sizeLimit=0, timeLimit=50, perRecordCallback=parser)
        except ldap.LDAPSearchError as e:
            raise Exception("ldap_query error: {}".format(str(e)))

    def ldap_query(self, search, attrs, parser):
        self.data = {}
        self.execute_query(search, attrs, parser)
        return self.data

    ##################################################
    # Ldap Search Types
    ##################################################
    def user_query(self, query, attrs, all_users=False):
        if attrs:
            ATTRIBUTES['users'] = ATTRIBUTES['users'] + attrs

        search = QUERIES['users_active']
        if all_users:
            # Query all users, even disabled
            search = QUERIES['users_all']
        elif '@' in query:
            search = QUERIES['users_email_search'].format(query.lower())
        elif query and query not in ['active', 'Active', '{active}']:
            search = QUERIES['users_account_search'].format(query.lower())

        return self.ldap_query(search, ATTRIBUTES['users'], self.generic_parser)

    def computer_query(self, query, attrs):
        if attrs:
            ATTRIBUTES['cpu'] = ATTRIBUTES['cpu'] + attrs

        if query and query != 'eol':
            self.ldap_query(QUERIES['cpu_search'].format(query), ATTRIBUTES['cpu'], self.generic_parser)
        else:
            self.ldap_query(QUERIES['cpu_all'], ATTRIBUTES['cpu'], self.generic_parser)

        if query == "eol":
            self.data = self.eol_filter(self.data)
        return self.data

    def group_query(self, attrs):
        if attrs:
            ATTRIBUTES['groups'] = ATTRIBUTES['groups'] + attrs
        return self.ldap_query(QUERIES['groups_all'], attrs, self.generic_parser)

    def group_membership(self, group, attrs):
        ATTRS = ['member']
        if attrs:
            ATTRS = ATTRS + attrs
        return self.ldap_query(QUERIES['group_members'].format(group), ATTRS, self.group_membership_parser)

    def domain_query(self, attrs):
        if attrs:
            ATTRIBUTES['domain'] = ATTRIBUTES['domain'] + attrs
        return self.ldap_query(QUERIES['domain_policy'], ATTRIBUTES['domain'], self.generic_parser)

    def trust_query(self, attrs):
        if attrs:
            ATTRIBUTES['trust'] = ATTRIBUTES['trust'] + attrs
        return self.ldap_query(QUERIES['domain_trust'], ATTRIBUTES['trust'], self.generic_parser)

    def custom_query(self, query, attrs):
        if not query or not attrs:
            raise Exception("Query / Attributes not provided for custom LDAP search")
        return self.ldap_query(query, attrs, self.generic_parser)

    ##################################################
    # LDAP Data Parsers
    ##################################################
    def convert(self, attr, value):
        try:
            if attr in ['lockOutObservationWindow', 'lockoutDuration']:
                # Min
                tmp = (abs(float(value)) * .0000001) / 60
                value = str(tmp) + " Min."

            elif attr in ['maxPwdAge', 'minPwdAge']:
                tmp = (abs(float(value)) * .0000001) / 86400
                value = str(tmp) + " Days"

        except Exception as e:
            pass
        return value

    def generic_parser(self, resp):
        tmp = {}
        dtype = ''
        resp_data = ''
        try:
            for attr in resp['attributes']:
                dtype = str(attr['type'])

                # catch formatting issues
                if "SetOf:" in str(attr['vals']):
                    resp_data = str(attr['vals'][0])
                else:
                    resp_data = str(attr['vals'])

                resp_data = self.convert(dtype, resp_data)
                tmp[dtype] = resp_data

            self.categorize(tmp)
            del (tmp)
        except:
            pass

    def group_membership_parser(self, resp):
        try:
            for attr in resp['attributes']:
                for member in attr['vals']:
                    cn = str(member).split(',')[0]
                    search = "(&({}))".format(cn)
                    self.execute_query(search, ATTRIBUTES['users'], self.generic_parser)
        except:
            pass

    def no_parser(self, resp):
        # Used for custom queries not tested with parsers
        print(resp)

    def eol_filter(self, resp):
        # Parse results looking for end of life systems
        data = {}
        for k, v in resp.items():
            try:
                if str(v['operatingSystemVersion']).startswith(('3', '4', '5', '6.0')):
                    data[k] = v
            except:
                pass
        return data

    def categorize(self, tmp):
        # Take temp data, sort and move to class object
        for x in ['sAMAccountName', 'dNSHostName', 'cn', 'dc']:
            try:
                self.data[tmp[x]] = tmp
                return
            except:
                pass

    ##################################################
    # Ldap Close Connection
    ##################################################
    def close(self):
        try:
            self.con.close()
            self.con._socket = None
            self.con = None
        except:
            pass
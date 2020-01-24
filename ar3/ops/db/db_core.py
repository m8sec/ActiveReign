from sqlite3 import connect
from os import remove, path

class Ar3db():
    __sql_create_domains      = ('CREATE TABLE IF NOT EXISTS DOMAINS (DOMAINID INTEGER PRIMARY KEY AUTOINCREMENT,'
                                 'NAME TEXT NOT NULL,'
                                 'LOCKOUT_THRESHOLD INTEGER,'
                                 'LOCKOUT_DURATION TEXT,'
                                 'MIN_PWD_LENGTH INTEGER,'
                                 'MAX_PWD_AGE TEXT);')

    __sql_create_hosts        = ('CREATE TABLE IF NOT EXISTS HOSTS (HOSTID INTEGER PRIMARY KEY AUTOINCREMENT,'
                                 'HOSTNAME TEXT,'
                                 'IP TEXT,'
                                 'DOMAIN TEXT,'
                                 'OS TEXT,'
                                 'SIGNING BOOL);')

    __sql_create_users        = ('CREATE TABLE IF NOT EXISTS USERS (USERID INTEGER PRIMARY KEY AUTOINCREMENT,'
                                 'USERNAME TEXT NOT NULL,'
                                 'PASSWORD TEXT,'
                                 'DOMAIN TEXT,'
                                 'HASH TEXT);')

    __sql_create_admin        = ('CREATE TABLE IF NOT EXISTS ADMINS (ADMINID INTEGER PRIMARY KEY AUTOINCREMENT,'
                                 'HOSTID INTEGER NOT NULL,'
                                 'USERID INTEGER NOT NULL);')

    __sql_create_groups       = ('CREATE TABLE IF NOT EXISTS GROUPS (GROUPID INTEGER PRIMARY KEY AUTOINCREMENT,'
                                 'DOMAIN TEXT,'
                                 'NAME TEXT NOT NULL);')

    __sql_create_user_members = ('CREATE TABLE IF NOT EXISTS MEMBERS_USERS (MEMBERID INTEGER PRIMARY KEY AUTOINCREMENT,'
                                 'GROUPID INTEGER NOT NULL,'
                                 'USERID INTEGER NOT NULL);')

    __sql_create_group_members = ('CREATE TABLE IF NOT EXISTS MEMBERS_GROUPS (MEMBERID INTEGER PRIMARY KEY AUTOINCREMENT,'
                                  'GROUPID INTEGER NOT NULL,'
                                  'GMID INTEGER NOT NULL);')

    def __init__(self, workspace, logger, debug=False):
        self.logger = logger
        self.debug  = debug
        self.db_dir = path.join(path.expanduser('~'), '.ar3', 'workspaces', workspace)
        self.dbname = path.join(self.db_dir, 'ar3.db')

    ###########################
    # DB connection/interaction
    ###########################
    def db_connect(self, dbname):
        try:
            return connect(dbname, timeout=3, check_same_thread=False)
        except Exception as e:
            self.logger.debug(str(e))
            return False

    def db_init(self):
        try:
            con = self.db_connect(self.dbname)
            self.db_exec(con, self.__sql_create_domains)
            self.db_exec(con, self.__sql_create_hosts)
            self.db_exec(con, self.__sql_create_users)
            self.db_exec(con, self.__sql_create_admin)
            self.db_exec(con, self.__sql_create_groups)
            self.db_exec(con, self.__sql_create_user_members)
            self.db_exec(con, self.__sql_create_group_members)
            con.close()
            return True
        except Exception as e:
            print(e)
            self.logger.debug(str(e))
            return False

    def db_exec(self, con, query):
        cur = con.cursor()
        cur.execute(query)
        data = cur.fetchall()
        con.commit()
        cur.close()
        return data

    def db_rebuild(self):
        try:
            self.db_remove()
            self.db_init()
            return True
        except:
            return False

    def db_remove(self):
        remove(self.dbname)

    def close(self,con):
        con.close()

    ###########################
    # Retrieve Unique ID
    ###########################
    def domain_id(self, con, domain):
        try:
            return self.db_exec(con, """SELECT DOMAINID FROM DOMAINS WHERE NAME='{}' LIMIT 1;""".format(domain))[0][0]
        except:
            return False

    def host_id(self, con, host):
        try:
            return self.db_exec(con, """SELECT HOSTID FROM HOSTS WHERE HOSTNAME='{}' LIMIT 1;""".format(host))[0][0]
        except:
            return False

    def user_id(self, con, username, domain):
        try:
            return self.db_exec(con, """SELECT USERID FROM USERS WHERE USERNAME='{}' AND DOMAIN='{}' LIMIT 1;""".format(username, domain))[0][0]
        except:
            return False

    def cred_id(self, con, username, domain, password, hash):
        try:
            return self.db_exec(con, """SELECT USERID FROM USERS WHERE USERNAME='{}' AND DOMAIN='{}' AND PASSWORD='{}' AND HASH='{}' LIMIT 1;""".format(username, domain, password, hash))[0][0]
        except:
            return False

    def group_id(self, con, group_name, domain):
        try:
            return self.db_exec(con, """SELECT GROUPID FROM GROUPS WHERE NAME='{}' AND DOMAIN='{}' LIMIT 1;""".format(group_name, domain))[0][0]
        except:
            return False

    ###########################
    # Update records
    ###########################
    def update_domain(self, domain, lockout_threshold):
        con = self.db_connect(self.dbname)
        id = self.domain_id(con, domain.lower())
        if id:
            self.db_exec(con, """UPDATE DOMAINS SET NAME='{}', LOCKOUT_THRESHOLD='{}' WHERE DOMAINID={};""".format(domain.lower(), lockout_threshold, id))
        else:
            self.db_exec(con, """INSERT INTO DOMAINS (NAME, LOCKOUT_THRESHOLD) VALUES ('{}','{}');""".format(domain.lower(), lockout_threshold))
        con.close()

    def update_domain_ldap(self, domain, threshold, duration, length, age):
        # Update all values in domain policy
        con = self.db_connect(self.dbname)
        id = self.domain_id(con, domain.lower())
        if id:
            self.db_exec(con, """UPDATE DOMAINS SET NAME='{}', LOCKOUT_THRESHOLD='{}', LOCKOUT_DURATION='{}', MIN_PWD_LENGTH='{}', MAX_PWD_AGE='{}' WHERE DOMAINID={};""".format(domain.lower(), threshold, duration, length, age, id))
        else:
            self.db_exec(con, """INSERT INTO DOMAINS (NAME, LOCKOUT_THRESHOLD, LOCKOUT_DURATION, MIN_PWD_LENGTH, MAX_PWD_AGE) VALUES ('{}','{}','{}','{}','{}');""".format(domain.lower(), threshold, duration, length, age))
        con.close()

    def update_host(self, hostname, ip, domain, os, signing):
        con = self.db_connect(self.dbname)
        id = self.host_id(con, hostname.lower())
        if id:
            self.db_exec(con,"""UPDATE HOSTS SET HOSTNAME='{}', IP='{}', DOMAIN='{}', OS='{}', SIGNING='{}' WHERE HOSTID={};""".format(hostname.lower(), ip, domain.lower(), os, signing, id))
        else:
            self.db_exec(con, """INSERT OR REPLACE INTO HOSTS(HOSTNAME, IP, DOMAIN, OS, signing) VALUES ('{}','{}','{}','{}', '{}');""".format(hostname.lower(), ip, domain.lower(), os, signing))
        con.close()

    def update_host_ldap(self, hostname, ip, domain, os):
        # Update host using ldap information
        con = self.db_connect(self.dbname)
        id = self.host_id(con, hostname.lower())
        if id:
            self.db_exec(con,"""UPDATE HOSTS SET HOSTNAME='{}', IP='{}', DOMAIN='{}', OS='{}' WHERE HOSTID={};""".format(hostname.lower(), ip, domain.lower(), os, id))
        else:
            self.db_exec(con, """INSERT OR REPLACE INTO HOSTS(HOSTNAME, IP, DOMAIN, OS) VALUES ('{}','{}','{}','{}');""".format(hostname.lower(), ip, domain.lower(), os))
        con.close()


    def update_user(self, username, passwd, domain, hash):
        con = self.db_connect(self.dbname)
        id = self.user_id(con, username.lower(), domain.lower())
        if id:
            self.db_exec(con,"""UPDATE USERS SET USERNAME='{}', PASSWORD='{}', DOMAIN='{}', HASH='{}' WHERE USERID={};""".format(username.lower(), passwd, domain.lower(), hash, id))
        else:
            self.db_exec(con,"""INSERT INTO USERS (USERNAME, PASSWORD, DOMAIN, HASH) VALUES ('{}','{}','{}','{}');""".format(username.lower(), passwd, domain.lower(), hash))
        con.close()

    def update_username(self, domain, username):
        # Update username and domain values without effecting password/hash values
        con = self.db_connect(self.dbname)
        uid = self.user_id(con, username.lower(), domain.lower())
        if uid:
            self.db_exec(con, """UPDATE USERS SET USERNAME='{}', DOMAIN='{}' WHERE USERID={};""".format(username.lower(), domain.lower(), uid))
        else:
            self.db_exec(con, """INSERT INTO USERS (USERNAME, DOMAIN) VALUES ('{}','{}');""".format(username.lower(), domain.lower()))
        con.close()

    def update_user_members(self, domain, username, group_name):
        con = self.db_connect(self.dbname)
        uid = self.user_id(con, username.lower(), domain.lower())
        gid = self.group_id(con, group_name, domain.lower())
        self.db_exec(con, """INSERT INTO MEMBERS_USERS (GROUPID, USERID) SELECT '{0}', '{1}' WHERE NOT EXISTS(SELECT MEMBERID FROM MEMBERS_USERS WHERE GROUPID={0} AND USERID={1});""".format(gid, uid))
        con.close()

    def update_group_members(self, domain, group_member, group_name):
        con = self.db_connect(self.dbname)
        gmid = self.group_id(con, group_member, domain.lower())
        gid = self.group_id(con, group_name, domain.lower())
        self.db_exec(con, """INSERT INTO MEMBERS_GROUPS (GROUPID, GMID) SELECT '{0}', '{1}' WHERE NOT EXISTS(SELECT MEMBERID FROM MEMBERS_GROUPS WHERE GROUPID={0} AND GMID={1});""".format(gid, gmid))
        con.close()
        return

    def update_group(self, group_name, domain):
        try:
            group_name = group_name.replace("'", "").replace('"', "")
            con = self.db_connect(self.dbname)
            id = self.group_id(con, group_name, domain.lower())
            if id:
                self.db_exec(con,"""UPDATE GROUPS SET DOMAIN='{}', NAME='{}' WHERE GROUPID={};""".format(domain.lower(), str(group_name), id))
            else:
                self.db_exec(con,"""INSERT INTO GROUPS (DOMAIN, NAME) VALUES ('{}','{}');""".format(domain.lower(), str(group_name)))
            con.close()
        except Exception as e:
            self.logger.debug(['DB GROUPS', group_name, domain, str(e)])

    def update_admin(self, username, domain, hostname):
        con = self.db_connect(self.dbname)
        hid = self.host_id(con, hostname.lower())
        uid = self.user_id(con, username.lower(), domain.lower())
        self.db_exec(con, """INSERT INTO ADMINS (USERID, HOSTID) SELECT '{0}', '{1}' WHERE NOT EXISTS(SELECT ADMINID FROM ADMINS WHERE USERID={0} AND HOSTID={1});""".format(uid, hid))
        con.close()

    ###########################
    # General queries (Returns all data)
    ###########################
    def query_domains(self):
        try:
            con = self.db_connect(self.dbname)
            tmp = self.db_exec(con, """SELECT * FROM DOMAINS;""")
            con.close()
            return tmp
        except Exception as e:
            self.logger.debug(str(e))
            return [[]]

    def query_groups(self):
        try:
            con = self.db_connect(self.dbname)
            tmp = self.db_exec(con, """SELECT GROUPS.GROUPID, GROUPS.DOMAIN, GROUPS.NAME, (SELECT (COUNT(MEMBERS_USERS.USERID)|| ' User(s)') FROM MEMBERS_USERS WHERE MEMBERS_USERS.GROUPID = GROUPS.GROUPID), (SELECT (COUNT(MEMBERS_GROUPS.GMID)|| ' Group(s)') FROM MEMBERS_GROUPS WHERE MEMBERS_GROUPS.GROUPID = GROUPS.GROUPID) FROM GROUPS ORDER BY GROUPS.NAME;""")
            con.close()
            return tmp
        except Exception as e:
            self.logger.debug(str(e))
            return [[]]

    def query_hosts(self):
        try:
            con = self.db_connect(self.dbname)
            tmp = self.db_exec(con, """SELECT HOSTS.HOSTID, HOSTS.DOMAIN, HOSTS.HOSTNAME, HOSTS.IP, HOSTS.OS, HOSTS.SIGNING, (SELECT (COUNT(ADMINS.USERID) || ' User(s)') FROM ADMINS WHERE ADMINS.HOSTID = HOSTS.HOSTID) FROM HOSTS;""")
            con.close()
            return tmp
        except Exception as e:
            self.logger.debug(str(e))
            return [[]]

    def query_users(self):
        try:
            con = self.db_connect(self.dbname)
            tmp = self.db_exec(con, """SELECT USERS.USERID, USERS.DOMAIN, USERS.USERNAME, USERS.PASSWORD, USERS.HASH, (SELECT (COUNT(ADMINS.HOSTID) || ' Host(s)') FROM ADMINS WHERE ADMINS.USERID = USERS.USERID), (SELECT (COUNT(MEMBERS_USERS.GROUPID) || ' Groups(s)') FROM MEMBERS_USERS WHERE MEMBERS_USERS.USERID = USERS.USERID) FROM USERS ORDER BY USERS.USERNAME;""")
            con.close()
            return tmp
        except Exception as e:
            self.logger.debug(str(e))
            return [[]]

    def query_creds(self):
        try:
            con = self.db_connect(self.dbname)
            tmp = self.db_exec(con, """SELECT USERS.USERID, USERS.DOMAIN, USERS.USERNAME, USERS.PASSWORD, USERS.HASH, (SELECT (COUNT(ADMINS.HOSTID) || ' Host(s)') FROM ADMINS WHERE ADMINS.USERID = USERS.USERID) FROM USERS WHERE USERS.hash iS NOT NULL OR USERS.PASSWORD IS NOT NULL;""")
            con.close()
            return tmp
        except Exception as e:
            self.logger.debug(str(e))
            return [[]]

    ###########################
    # Query specific value
    ###########################
    def custom_query(self, sql):
        try:
            con = self.db_connect(self.dbname)
            tmp = self.db_exec(con, sql)
            con.close()
            return tmp
        except Exception as e:
            self.logger.debug(str(e))
            return [[]]

    def query_spec_host(self, search):
        try:
            con = self.db_connect(self.dbname)
            tmp = self.db_exec(con, """SELECT HOSTS.HOSTID, HOSTS.DOMAIN, HOSTS.HOSTNAME, HOSTS.IP, HOSTS.OS, HOSTS.SIGNING, USERS.USERNAME, USERS.DOMAIN, USERS.PASSWORD, USERS.HASH FROM HOSTS INNER JOIN ADMINS ON HOSTS.HOSTID = ADMINS.HOSTID INNER JOIN USERS ON USERS.USERID = ADMINS.USERID WHERE {};""".format(search))
            con.close()
            return tmp
        except Exception as e:
            self.logger.debug(str(e))
            return [[]]


    ###############################
    # Extract value for use in Enum
    ###############################
    def extract_user(self, userid):
        # Used to extract creds from db for enumeration
        try:
            con = self.db_connect(self.dbname)
            tmp = self.db_exec(con, """SELECT USERNAME, PASSWORD, HASH, DOMAIN FROM USERS WHERE USERID={}""".format(userid))
            con.close()
            return tmp
        except Exception as e:
            return [[]]

    def extract_lockout(self, domain):
        tmp = False
        con = self.db_connect(self.dbname)
        try:
            id = self.domain_id(con, domain)
            tmp = self.db_exec(con, """SELECT LOCKOUT_THRESHOLD FROM DOMAINS WHERE DOMAINID={} LIMIT 1;""".format(id))[0][0]
        except:
            pass
        con.close()
        return tmp

    def extract_credID(self, username, domain, password, hash):
        con = self.db_connect(self.dbname)
        id = self.cred_id(con, username, domain, password, hash)
        con.close()
        return id

    def pwd_check(self, domain, username):
        # Domain pwd spray, check creds dont exist in DB
        tmp = False
        con = self.db_connect(self.dbname)
        try:
            con = self.db_connect(self.dbname)
            tmp = self.db_exec(con, """SELECT PASSWORD FROM USERS WHERE DOMAIN='{}' AND USERNAME='{}' LIMIT 1""".format(domain, username))[0][0]
        except:
            pass
        con.close()
        return tmp
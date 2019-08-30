from sqlite3 import connect
from os import remove, path

class Ar3db():
    __sql_create_domains = ('CREATE TABLE IF NOT EXISTS DOMAINS (DOMAINID INTEGER PRIMARY KEY AUTOINCREMENT,'
                            'DOMAIN TEXT NOT NULL,'
                            'LOCKOUT_THRESHOLD INTEGER);')

    __sql_create_hosts = ('CREATE TABLE IF NOT EXISTS HOSTS (HOSTID INTEGER PRIMARY KEY AUTOINCREMENT,'
                          'HOSTNAME TEXT,'
                          'IP TEXT,'
                          'DOMAIN TEXT,'
                          'OS TEXT,'
                          'SIGNING BOOL);')

    __sql_create_users = ('CREATE TABLE IF NOT EXISTS USERS (USERID INTEGER PRIMARY KEY AUTOINCREMENT,'
                          'USERNAME TEXT NOT NULL,'
                          'PASSWORD TEXT,'
                          'DOMAIN TEXT,'
                          'HASH TEXT);')

    __sql_create_admin = ('CREATE TABLE IF NOT EXISTS ADMIN (ADMINID INTEGER PRIMARY KEY AUTOINCREMENT,'
                          'HOSTID INTEGER NOT NULL,'
                          'USERID INTEGER NOT NULL);')

    def __init__(self, workspace, logger, debug=False):
        self.logger = logger
        self.debug  = debug
        self.db_dir = path.join(path.expanduser('~'), '.ar3', 'workspaces', workspace)
        self.dbname = path.join(self.db_dir, 'ar3.db')

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
            con.close()
            return True
        except Exception as e:
            self.logger.debug(str(e))
            return False

    def db_exec(self, con, query):
        cur = con.cursor()
        cur.execute(query)
        data = cur.fetchall()
        con.commit()
        cur.close()
        return data

    def db_delete(self):
        try:
            remove(self.dbname)
            return True
        except:
            return False

    def close(self,con):
        con.close()

    def domain_id(self, con, domain):
        try:
            return self.db_exec(con, """SELECT DOMAINID FROM DOMAINS WHERE DOMAIN='{}' LIMIT 1;""".format(domain))[0][0]
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

    def update_domain(self, domain, lockout_threshold):
        con = self.db_connect(self.dbname)
        id = self.domain_id(con, domain)
        if id:
            self.db_exec(con, """UPDATE DOMAINS SET DOMAIN='{}', LOCKOUT_THRESHOLD='{}' WHERE DOMAINID={};""".format(domain, lockout_threshold, id))
        else:
            self.db_exec(con, """INSERT INTO DOMAINS (DOMAIN, LOCKOUT_THRESHOLD) VALUES ('{}','{}');""".format(domain, lockout_threshold))
        con.close()

    def update_host(self, hostname, ip, domain, os, signing):
        con = self.db_connect(self.dbname)
        id = self.host_id(con, hostname)
        if id:
            self.db_exec(con,"""UPDATE HOSTS SET HOSTNAME='{}', IP='{}', DOMAIN='{}', OS='{}', SIGNING='{}' WHERE HOSTID={};""".format(hostname, ip, domain, os, signing, id))
        else:
            self.db_exec(con, """INSERT OR REPLACE INTO HOSTS(HOSTNAME, IP, DOMAIN, OS, signing) VALUES ('{}','{}','{}','{}', '{}');""".format(hostname, ip, domain, os, signing))
        con.close()

    def update_user(self, username, passwd, domain, hash):
        con = self.db_connect(self.dbname)
        id = self.user_id(con, username, domain)
        if id:
            self.db_exec(con,"""UPDATE USERS SET USERNAME='{}', PASSWORD='{}', DOMAIN='{}', HASH='{}' WHERE USERID={};""".format(username, passwd, domain, hash, id))
        else:
            self.db_exec(con,"""INSERT INTO USERS (USERNAME, PASSWORD, DOMAIN, HASH) VALUES ('{}','{}','{}','{}');""".format(username, passwd, domain, hash))
        con.close()

    def update_admin(self, username, domain, hostname):
        con = self.db_connect(self.dbname)
        hid = self.host_id(con, hostname)
        uid = self.user_id(con, username, domain)
        self.db_exec(con, """INSERT INTO ADMIN (USERID, HOSTID) SELECT '{0}', '{1}' WHERE NOT EXISTS(SELECT ADMINID FROM ADMIN WHERE USERID={0} AND HOSTID={1});""".format(uid, hid))
        con.close()

    def query_domains(self):
        try:
            con = self.db_connect(self.dbname)
            tmp = self.db_exec(con, """SELECT * FROM DOMAINS;""")
            con.close()
            return tmp
        except Exception as e:
            self.logger.debug(str(e))
            return [[]]

    def query_hosts(self):
        try:
            con = self.db_connect(self.dbname)
            tmp = self.db_exec(con, """SELECT HOSTS.HOSTID, HOSTS.HOSTNAME, HOSTS.IP, HOSTS.DOMAIN, HOSTS.OS, HOSTS.SIGNING, (SELECT (COUNT(ADMIN.USERID) || ' User(s)') FROM ADMIN WHERE ADMIN.HOSTID = HOSTS.HOSTID) FROM HOSTS;""")
            con.close()
            return tmp
        except Exception as e:
            self.logger.debug(str(e))
            return [[]]

    def query_users(self):
        try:
            con = self.db_connect(self.dbname)
            tmp = self.db_exec(con, """SELECT USERS.USERID, USERS.USERNAME, USERS.PASSWORD, USERS.HASH, USERS.DOMAIN, (SELECT (COUNT(ADMIN.HOSTID) || ' Host(s)') FROM ADMIN WHERE ADMIN.USERID = USERS.USERID) FROM USERS;""")
            con.close()
            return tmp
        except Exception as e:
            self.logger.debug(str(e))
            return [[]]

    def query_specific_user(self, userid):
        try:
            con = self.db_connect(self.dbname)
            tmp = self.db_exec(con, """SELECT USERS.USERID, USERS.USERNAME, USERS.PASSWORD, USERS.HASH, USERS.DOMAIN, HOSTS.HOSTNAME, HOSTS.IP, HOSTS.OS FROM USERS INNER JOIN ADMIN ON USERS.USERID = ADMIN.USERID INNER JOIN HOSTS ON ADMIN.HOSTID = HOSTS.HOSTID WHERE USERS.USERID = '{}';""".format(userid))
            con.close()
            return tmp
        except Exception as e:
            self.logger.debug(str(e))
            return [[]]

    def query_specific_host(self, hostid):
        try:
            con = self.db_connect(self.dbname)
            tmp = self.db_exec(con, """SELECT HOSTS.HOSTID, HOSTS.HOSTNAME, HOSTS.IP, HOSTS.DOMAIN, HOSTS.OS, HOSTS.SIGNING, USERS.USERNAME FROM HOSTS INNER JOIN ADMIN ON HOSTS.HOSTID = ADMIN.HOSTID INNER JOIN USERS ON USERS.USERID = ADMIN.USERID WHERE HOSTS.HOSTID = '{}';""".format(hostid))
            con.close()
            return tmp
        except Exception as e:
            self.logger.debug(str(e))
            return [[]]

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
        try:
            con = self.db_connect(self.dbname)
            id = self.domain_id(con, domain)
            tmp = self.db_exec(con, """SELECT LOCKOUT_THRESHOLD FROM DOMAINS WHERE DOMAINID={} LIMIT 1;""".format(id))[0][0]
            con.close()
            return tmp
        except Exception as e:
            return False

    def del_db(self):
        remove(self.dbname)
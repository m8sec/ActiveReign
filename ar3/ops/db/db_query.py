"""
Functions to interact with db_core for querying
all database objects, called by db_shell
and __init__ for command line access in AR3.
"""
from terminaltables import AsciiTable

def rebuild(db_obj, logger):
    try:
        db_obj.db_rebuild()
        logger.success("Database has been rebuilt")
    except Exception as e:
        logger.fail(str(e))


def domains(db_obj, logger):
    select_data = db_obj.query_domains()
    db_title = "DOMAINS"
    header = [("DOMAIN ID", "DOMAIN", "LOCKOUT THRESHOLD", "LOCKOUT DURATION", "MIN PWD LENGTH", "MAX PWD AGE")]
    display_data(select_data, logger, db_title, header)


def hosts(db_obj, logger):
    select_data = db_obj.query_hosts()
    header = [("HOSTID", "DOMAIN", "HOSTNAME", "IP", "OS", "SIGNING", "ADMIN(s)")]
    db_title = "HOSTS"
    display_data(select_data, logger, db_title, header)


def host_lookup(db_obj, logger, id):
    select_data = db_obj.query_spec_host(id)
    header = [("HOSTID", "DOMAIN", "HOSTNAME", "IP", "OS", "SIGNING", "ADMIN(s)", "USER DOMAIN", "PASSWORD", "HASH")]
    db_title = "HOST"
    display_data(select_data, logger, db_title, header)


def users(db_obj, logger):
    select_data = db_obj.query_users()
    header = [("USERID", "DOMAIN", "USERNAME", "PASSWORD", "HASH", "ADMIN ON", "MEMBER OF")]
    db_title = "USERS"
    display_data(select_data, logger, db_title, header)


def user_lookup(db_obj, logger, id):
    # User Lookup
    sql = """SELECT USERS.USERID, USERS.DOMAIN, USERS.USERNAME, USERS.PASSWORD, USERS.HASH FROM USERS WHERE USERS.USERID = '{}';""".format(id)
    select_data = db_obj.custom_query(sql)
    header = [("USERID", "DOMAIN", "USERNAME", "PASSWORD", "HASH")]
    db_title = "USER"
    display_data(select_data, logger, db_title, header)

    # User Host Lookup
    sql = """SELECT USERS.USERID, USERS.DOMAIN, USERS.USERNAME, HOSTS.HOSTID, HOSTS.DOMAIN, HOSTS.HOSTNAME, HOSTS.IP, HOSTS.OS FROM USERS INNER JOIN ADMINS ON USERS.USERID = ADMINS.USERID INNER JOIN HOSTS ON ADMINS.HOSTID = HOSTS.HOSTID WHERE USERS.USERID = '{}';""".format(id)
    select_data = db_obj.custom_query(sql)
    header = [("USERID", "DOMAIN", "USERNAME", "HOSTID", "HOST DOMAIN", "HOSTNAME", "IP", "OS")]
    db_title = "HOSTS"
    display_data(select_data, logger, db_title, header)

    # User Member Lookup
    sql = """SELECT USERS.USERID, USERS.DOMAIN, USERS.USERNAME, GROUPS.GROUPID, GROUPS.DOMAIN, GROUPS.NAME FROM USERS INNER JOIN MEMBERS_USERS ON USERS.USERID = MEMBERS_USERS.USERID INNER JOIN GROUPS ON MEMBERS_USERS.GROUPID = GROUPS.GROUPID WHERE USERS.USERID = '{}';""".format(id)
    select_data = db_obj.custom_query(sql)
    header = [("USERID", "DOMAIN", "USERNAME", "GROUPID", "GROUP DOMAIN", "GROUP NAME")]
    db_title = "GROUPS"
    display_data(select_data, logger, db_title, header)


def creds(db_obj, logger):
    select_data = db_obj.query_creds()
    header = [("USERID", "DOMAIN", "USERNAME", "PASSWORD", "HASH", "ADMIN ON")]
    db_title = "CREDS"
    display_data(select_data, logger, db_title, header)

def groups(db_obj, logger):
    select_data = db_obj.query_groups()
    header = [("GROUPID", "DOMAIN", "NAME", "MEMBERS: USERS", "MEMBERS: GROUPS")]
    db_title = "GROUPS"
    display_data(select_data, logger, db_title, header)

def group_lookup(db_obj, logger, id):
    sql="""SELECT GROUPS.GROUPID, GROUPS.DOMAIN, GROUPS.NAME, USERS.USERID, USERS.USERNAME, USERS.DOMAIN, USERS.PASSWORD, USERS.HASH FROM GROUPS INNER JOIN MEMBERS_USERS ON MEMBERS_USERS.GROUPID = GROUPS.GROUPID INNER JOIN USERS ON MEMBERS_USERS.USERID = USERS.USERID WHERE GROUPS.GROUPID = '{}';""".format(id)
    select_data = db_obj.custom_query(sql)
    header = [("GROUPID", "DOMAIN", "NAME", "USERID", "USERNAME", "USER DOMAIN", "PASSWORD", "HASH")]
    db_title = "MEMBERS: USERS"
    display_data(select_data, logger, db_title, header)

    sql = """SELECT GROUPS.GROUPID, GROUPS.DOMAIN, GROUPS.NAME, MEMBERS_GROUPS.GMID,(SELECT GROUPS.DOMAIN FROM GROUPS WHERE GROUPS.GROUPID = MEMBERS_GROUPS.GMID), (SELECT GROUPS.NAME FROM GROUPS WHERE GROUPS.GROUPID = MEMBERS_GROUPS.GMID) FROM GROUPS INNER JOIN MEMBERS_GROUPS ON GROUPS.GROUPID = MEMBERS_GROUPS.GROUPID WHERE GROUPS.GROUPID = '{}';""".format(id)
    select_data = db_obj.custom_query(sql)
    header = [("GROUPID", "DOMAIN", "NAME", "GROUP MEMBER ID", "GROUP MEMBER DOMAIN", "GROUP MEMBER NAME")]
    db_title = "MEMBERS: GROUPS"
    display_data(select_data, logger, db_title, header)


def display_data(data, logger, db_title=None, headers=''):
    # Display data in ascii table format
    if data:
        table = AsciiTable(headers + data)
        if db_title:
            table.title = db_title
        logger.output(table.table)
from terminaltables import AsciiTable

from ar3.ops.db.db_core import Ar3db


def main(args, config_obj, db_obj, loggers):
    header      = []
    select_data = [[]]
    logger = loggers['console']

    # Insert & Delete
    if args.db_table[0] in ['insert']:
        con = db_obj.db_connect(db_obj.dbname)
        # Update Domain
        if args.domain and args.lockout_threshold:
            db_obj.update_domain(args.domain, args.lockout_threshold)
            logger.success("{} was added successfully added to the database (Threshold: {})\n".format(args.domain, args.lockout_threshold))

        # Update user
        if args.user and args.domain:
            db_obj.update_user(args.user, args.password, args.domain, args.hash)
            logger.success("User {} was added successfully added to the database (USERID: {})\n".format(args.user, db_obj.user_id(con, args.user, args.domain)))
        con.close()
        return

    elif args.db_table[0] in ['delete']:
        db_obj.del_db()
        logger.success("Database Deleted")
        return

    # Data Queries
    elif args.db_table[0] in ['domain', 'domains']:
        select_data = db_obj.query_domains()
        db_title = "DOMAINS"
        header = [("DOMAIN ID","DOMAIN","LOCKOUT THRESHOLD")]

    elif args.db_table[0] in ['host', 'hosts']:
        if args.id:
            select_data = db_obj.query_specific_host(args.id)
            header = [("HOSTID", "HOSTNAME", "IP", "DOMAIN", "OS", "SIGNING", "ADMIN(s)")]
        else:
            select_data = db_obj.query_hosts()
            header = [("HOSTID", "HOSTNAME", "IP", "DOMAIN", "OS", "SIGNING", "ADMIN(s)")]
        db_title = "HOSTS"

    elif args.db_table[0] in ['user', 'users', 'creds']:
        if args.id:
            select_data = db_obj.query_specific_user(args.id)
            header = [("USERID", "USERNAME", "PASSWORD", "HASH", "DOMAIN", "ADMIN ON (HOSTNAME)", "ADMIN ON (IP)", "ADMIN ON (OS)" )]
        else:
            select_data = db_obj.query_users()
            header = [("USERID", "USERNAME", "PASSWORD", "HASH", "DOMAIN", "ADMIN ON")]
        db_title = "USERS"

    display_data(select_data, logger, db_title, header)


def display_data(data, logger, db_title=None, headers=''):
    if data:
        table = AsciiTable(headers+data)
        if db_title:
            table.title = db_title
        logger.output(table.table)
    else:
        logger.warning("No data returned, get to work!\n")
from ar3.ops.db import db_query
from ar3.ops.db import db_shell
from ar3.ops.db.db_core import Ar3db


def main(args, config_obj, db_obj, loggers):
    '''
    Execute by AR3 when db is used as the operational mode
    References queries in db_query, also used by ar3db shell
    entry point
    '''
    if args.db_table == 'insert':
        con = db_obj.db_connect(db_obj.dbname)
        # Update Domain
        if args.domain and args.lockout_threshold:
            db_obj.update_domain(args.domain, args.lockout_threshold)
            loggers['console'].success("{} was added successfully added to the database (Threshold: {})\n".format(args.domain, args.lockout_threshold))

        # Update user
        if args.user and args.domain:
            db_obj.update_user(args.user, args.password, args.domain, args.hash)
            loggers['console'].success("User {} was added successfully added to the database (USERID: {})\n".format(args.user, db_obj.user_id(con, args.user, args.domain)))
        con.close()
        return

    if args.db_table == 'rebuild':
        db_query.rebuild(db_obj, loggers['console'])

    elif args.db_table == 'domains':
        db_query.domains(db_obj, loggers['console'])

    elif args.db_table == 'hosts':
        if args.id:
            db_query.host_lookup(db_obj, loggers['console'], args.id)
        else:
            db_query.hosts(db_obj, loggers['console'])

    elif args.db_table== 'users':
        if args.id:
            db_query.user_lookup(db_obj, loggers['console'], args.id)
        else:
            db_query.users(db_obj, loggers['console'])

    elif args.db_table== 'creds':
        if args.id:
            db_query.user_lookup(db_obj, loggers['console'], args.id)
        else:
            db_query.creds(db_obj, loggers['console'])

    elif args.db_table== 'groups':
        if args.id:
            db_query.group_lookup(db_obj, loggers['console'], args.id)
        else:
            db_query.groups(db_obj, loggers['console'])

    elif args.db_table == 'shell':
        db_shell.shell(loggers['console'])
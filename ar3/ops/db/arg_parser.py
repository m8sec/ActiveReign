from sys import exit

def db_args(sub_parser):
    usage = """
    Inserts: activereign db insert -u admin -p Password1 -d demo.local
    """
    db_parser = sub_parser.add_parser("db", description=usage, help='- Query or insert data into database')
    db_parser.add_argument(dest='db_table', nargs='+', help='Ar3db to table query, use \"help\" for more')
    db_parser.add_argument('-id', dest='id', type=int, help='ID to query specific results')
    db_parser.add_argument('-u', dest='user', type=str, default='', help='Insert User account into db')
    db_parser.add_argument('-p', dest='password', type=str, default='', help='Insert into db: Password (Default: None)')
    db_parser.add_argument('-hash', dest='hash', type=str, default='', help='Insert into db: Hash (Default: None)')
    db_parser.add_argument('-d', dest='domain', type=str, default='', help='Insert into db: Domain')
    db_parser.add_argument('-t', '--threshold', dest='lockout_threshold', type=int, default=False, help='Domain/System Lockout Threshold')
    db_parser.add_argument('--rebuild', dest='rebuild', action='store_true', help='Rebuild database')

def db_arg_mods(args, db_obj, loggers):
    # Approved actions
    actions = ['insert', 'users', 'creds', 'hosts', 'computers', 'groups', 'domains', 'rebuild', 'info', 'shell', 'help']

    actions_help = """      \033[01;30mTables\n    >>------------>\033[0m
    domains   : List all domains
    users     : List all users
    creds     : List all credentials
    groups    : List all groups
    computers : List all computers
    
      \033[01;30mOperations\n    >>------------>\033[0m
    rebuild   : Delete current database and wipe all data
    insert    : Insert user or domain into database for enumeration
       user   : ar3 db insert -u admin -p password -d demo.local
       domain : ar3 db insert -d demo.local -t 5
    """

    args.db_table = args.db_table[0].lower()


    if args.db_table not in actions:
        loggers['console'].fail('Invalid operation requested: \"{}\"'.format(args.db_table))
        loggers['console'].fail('Use \"ar3 db help\" to list all options'.format(args.db_table))
        exit(1)
    elif args.db_table == 'help':
        loggers['console'].info("ActiveReign Database")
        loggers['console'].output(actions_help)
        exit(0)
    return args
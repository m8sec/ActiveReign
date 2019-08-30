def db_args(sub_parser):
    usage = """
    Inserts: activereign db insert -u admin -p Password1 -d demo.local
    """
    db_parser = sub_parser.add_parser("db", description=usage, help='- Query or insert data into database')
    db_parser.add_argument(dest='db_table', nargs='+', help='Ar3db to query: domains, hosts, users, insert')
    db_parser.add_argument('-id', dest='id', type=int, help='ID to query specific results')
    db_parser.add_argument('-u', dest='user', type=str, default='', help='Insert User account into db')
    db_parser.add_argument('-p', dest='password', type=str, default='', help='Insert into db: Password (Default: None)')
    db_parser.add_argument('-hash', dest='hash', type=str, default='', help='Insert into db: Hash (Default: None)')
    db_parser.add_argument('-d', dest='domain', type=str, default='', help='Insert into db: Domain')
    db_parser.add_argument('--threshold', dest='lockout_threshold', type=int, default=False, help='Domain/System Lockout Threshold')

def db_arg_mods(args, db_obj, logger):
    return args
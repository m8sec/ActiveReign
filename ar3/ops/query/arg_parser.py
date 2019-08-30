from os import path
from getpass import getpass

def file_exists(parser, filename):
    if not path.exists(filename):
        parser.error("Input file not found: {}".format(filename))
    return [x.strip() for x in open(filename)]

def query_args(sub_parser):
    query_parser = sub_parser.add_parser("query", help='- Perform LDAP queries on domain')

    # Output / Display Options
    query_parser.add_argument('-v', dest="verbose", action='store_true', help="Show attribute fields and values")
    query_parser.add_argument('-t', dest='timeout', type=int, default=3, help='Connection Timeout')

    query_parser.add_argument('lookup_type', nargs='?', help='Lookup Types: user, group, computer')
    query_parser.add_argument('-q', dest='query', type=str, default='', help='Specify user or group to query')
    query_parser.add_argument('-a', dest='attrs', type=str, default='', help='Specify attrs to query')

    # Authentication - User
    query_parser.add_argument('-id', dest='cred_id', type=int, help='Use creds from db for queries')
    query_parser.add_argument('-u', dest='user', type=str, default='', required=False, help='Set username (Default=null)')

    query_pwd = query_parser.add_mutually_exclusive_group(required=False)
    query_pwd.add_argument('-H','-hashes', dest='hash', type=str, default='', help='Use Hash for authentication')
    query_pwd.add_argument('-p', dest='passwd', type=str, default='', help='Set password (Default=null)')

    query_parser.add_argument('-d', dest='domain', type=str, default='', help='Domain (Ex. demo.local)')
    query_parser.add_argument('-srv','--ldap-srv', dest='srv', type=str, default='', help='LDAP Server (optional)')
    query_parser.add_argument('-r', dest="resolve", action='store_true', help="Use DNS to resolve host records (Good for recon)")

def parse_attrs(attrs):
    if not attrs:
        return []
    else:
        return attrs.split(",")

def query_arg_mods(args, db_obj, logger):
    args.attrs = parse_attrs(args.attrs)

    if args.hash:
        args.passwd.append(False)
    elif not args.passwd and args.user:
        # Get password if not provided
        args.passwd = [getpass("Enter password, or continue with null-value: ")]

    if args.cred_id and not args.user:
        enum_user = db_obj.extract_user(args.cred_id)
        if enum_user:
            args.user = enum_user[0][0]
            args.passwd = enum_user[0][1]
            args.hash = enum_user[0][2]
            args.domain = enum_user[0][3]
        else:
            logger.fail("Unable to gather credentials from db, try again")
            exit(1)
    if args.hash:
        logger.status(['Query Authentication', '{}\{} (Password: None) (Hash: True)'.format(args.domain, args.user)])
    else:
        logger.status(['Query Authentication', '{}\{} (Password: {}****) (Hash: False])'.format(args.domain, args.user, args.passwd[:1])])
    return args
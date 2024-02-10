import argparse
from os import path
from getpass import getpass

def file_exists(parser, filename):
    if not path.exists(filename):
        parser.error("Input file not found: {}".format(filename))
    return [x.strip() for x in open(filename)]

def query_args(sub_parser):
    query_parser = sub_parser.add_parser("query", help='- Perform LDAP queries on domain')

    # Output / Display Options
    query_parser.add_argument('-t', dest='timeout', type=int, default=3, help='Connection Timeout')
    query_parser.add_argument('-srv', '--ldap-srv', dest='ldap_srv', type=str, default='', help='LDAP Server')

    qtypes = query_parser.add_argument_group("Query Types")
    qtypes.add_argument('--users', dest="users", action='store_true', help="Query domain users")
    qtypes.add_argument('--groups', dest="groups", action='store_true', help="Query domain groups")
    qtypes.add_argument('--computers', dest="computers", action='store_true', help="Query domain computers")
    qtypes.add_argument('--domain', dest="qdomain", action='store_true', help="Query domain information")
    qtypes.add_argument('--trust', dest="trust", action='store_true', help="Enumerate domain trust relationships")
    qtypes.add_argument('--reversible-encryption', dest="reversible_encryption", action='store_true', help="Lookup users with reversible encryption")
    qtypes.add_argument('--pass-never-expire', dest="pass_never_expire", action='store_true',help="Lookup users whos password never expires")
    qtypes.add_argument('--pass-not-required', dest="pass_not_required", action='store_true',help="Lookup users with password not required")
    qtypes.add_argument('--recon', dest="recon", action='store_true',help="Perform recon on the domain and populates the AR3 database for enumeration")
    qtypes.add_argument('--custom', dest="custom", type=str, default='', help="Perform custom query")

    qoptions = query_parser.add_argument_group("Query Options")
    qoptions.add_argument('-q', '--query', dest='query', type=str, default='', help='Specify user, computer, or group to query')
    qoptions.add_argument('-a', dest='attrs', type=str, default='', help='Specify attrs to query')
    qoptions.add_argument('--all', dest='all', action='store_true', help='Enumerate all users (even disabled) or all groups & members')

    auth = query_parser.add_argument_group("Query Authentication")
    auth.add_argument('-id', dest='cred_id', type=int, help='Use creds from db for queries')
    auth.add_argument('-u', dest='user', type=str, default='', required=False, help='Set username (Default=null)')
    auth.add_argument('-d', dest='domain', type=str, default='', help='Domain Name')

    query_pwd = auth.add_mutually_exclusive_group(required=False)
    query_pwd.add_argument('-H','-hashes', dest='hash', type=str, default='', help='Use Hash for authentication')
    query_pwd.add_argument('-p', dest='passwd', type=str, default='', help='Set password (Default=null)')

    outdata = query_parser.add_argument_group("Output Options")
    outdata.add_argument('-v','--verbose', dest="verbose", action='store_true', help="Show attribute fields and values")
    outdata.add_argument('--data-only', dest="data_only", action='store_true', help="Show data only (Copy/Paste Format)")
    outdata.add_argument('--parse', dest="parse", action='store_true', help="Parse text fields for sensitive information")

    # Hidden Args: Required for execution methods to work but not applicable to the operational mode
    query_parser.add_argument('--local-auth', dest="local_auth", action='store_true', help=argparse.SUPPRESS)


def parse_attrs(attrs):
    if not attrs:
        return []
    else:
        return attrs.split(",")

def query_arg_mods(args, db_obj, loggers):
    logger     = loggers['console']
    args.attrs = parse_attrs(args.attrs)

    if args.hash:
        args.passwd.append(False)
    elif not args.passwd and args.user:
        args.passwd = [getpass("Enter password, or continue with null-value: ")]

    if args.cred_id and not args.user:
        enum_user = db_obj.extract_user(args.cred_id)
        if enum_user:
            args.user   = enum_user[0][0]
            args.passwd = enum_user[0][1]
            args.hash   = enum_user[0][2]
            args.domain = enum_user[0][3]
        else:
            logger.fail("Unable to gather credentials from db, try again")
            exit(1)

    if args.hash:
        logger.status(['Query Authentication', '{}\{} (Password: None) (Hash: True)'.format(args.domain, args.user)])
    else:
        logger.status(['Query Authentication', '{}\{} (Password: {}****) (Hash: False)'.format(args.domain, args.user, args.passwd[:1])])
    return args
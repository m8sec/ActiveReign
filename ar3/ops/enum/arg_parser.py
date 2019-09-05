import argparse
from sys import argv, exit
from getpass import getpass
from ipparser import ipparser

from ar3.core.ldap import LdapCon
from ar3.modules import list_modules

def enum_args(sub_parser):
    # Create Subparser
    enum_parser = sub_parser.add_parser("enum", help='- System enumeration & Module execution')

    if "-L" in argv:
        list_modules()
        exit(0)

    enum_parser.add_argument('-t', dest='timeout', type=int, default=5,help='Connection timeout')
    enum_parser.add_argument('--gen-relay-list', dest='gen_relay_list', action='store_true', help='Create a file of all hosts that dont require SMB signing')

    auth = enum_parser.add_argument_group("Host Authentication")
    auth.add_argument('-u', dest='user', type=str, default='', required=False,help='Set username (Default=null)')

    auth_pwd = auth.add_mutually_exclusive_group(required=False)
    auth_pwd.add_argument('-H', '-hashes', dest='hash', type=str, default='', help='Use Hash for authentication')
    auth_pwd.add_argument('-p', dest='passwd', type=str, default='', help='Set password (Default=null)')

    auth.add_argument('-id', dest='cred_id', type=int, help='Use creds from db for ldap queries/enumeration')

    auth_domain = auth.add_mutually_exclusive_group(required=False)
    auth_domain.add_argument('-d', dest='domain', type=str, default='', help='Set domain (Default=null)')
    auth_domain.add_argument('--local-auth', dest='local_auth', action='store_true', help='Authenticate to target host, no domain')
    enum_parser.add_argument('--threshold', dest='lockout_threshold', type=int, default=3,help='Domain/System Lockout Threshold ''(Exits 1 attempt before lockout)')

    enum = enum_parser.add_argument_group("Enumerating Options")
    enum.add_argument('--pass-pol', dest="passpol", action='store_true', help="Enumerate password policy")
    enum.add_argument('--loggedon', dest='loggedon', action='store_true', help='Enumerate logged on users')
    enum.add_argument('--sessions', dest='sessions', action='store_true', help='Enumerate active sessions')
    enum.add_argument('--services', dest='list_services', action='store_true', help='Show running services')
    enum.add_argument('--services-all', dest='all_services', action='store_true', help='Show all services')
    enum.add_argument('--tasklist', dest='list_processes', action='store_true', help='Show running processes')
    enum.add_argument('-s', '--sharefinder', dest="sharefinder", action='store_true',help="Find open file shares with READ access")

    creds = enum_parser.add_argument_group("Gathering Credentials")
    creds.add_argument('--sam', dest='sam', action='store_true', help='Dump local SAM db')

    wmi = enum_parser.add_argument_group("WMI Query")
    wmi.add_argument('--wmi', dest='wmi_query', type=str, default='', help='Execute WMI theory')
    wmi.add_argument('--wmi-namespace', dest='wmi_namespace', type=str, default='root\\cimv2', help='WMI namespace (Default: root\\cimv2)')

    modules = enum_parser.add_argument_group("Module Execution")
    modules.add_argument('-M', dest='module', type=str, default='', help='Use AR3 module')
    modules.add_argument('-o', dest='module_args', type=str, default='', help='Provide AR3 module arguments')
    modules.add_argument('-L', dest='list_modules', type=str, default='', help='List all available modules')

    spider = enum_parser.add_argument_group("Spidering")
    spider.add_argument('--spider', dest='spider', action='store_true',help='Crawl file share and look for sensitive info')
    spider.add_argument('--depth', dest='max_depth', type=int, default=5, help='Set scan depth (Default: 3)')
    spider.add_argument('--share', dest='share', type=str, default='', help='Define network share to scan: \'C$\'')
    spider.add_argument('--path', dest='start_path', type=str, default='/', help='Define starting path for share: \'/Windows/Temp/\'')
    spider.add_argument('--filename', dest="filename_only", action='store_true', help="Scan Filenames & extensions only")

    execution = enum_parser.add_argument_group("Command Execution")
    execution.add_argument('-x', dest='execute', type=str, default='', help='Command to execute on remote server')
    execution.add_argument('-X', dest='ps_execute', type=str, default='', help='Execute command with PowerShell (Not Currently Available)')
    execution.add_argument('--exec-method', dest='exec_method', type=str, default='wmiexec',help='Code execution method {wmiexec, smbexec}')
    execution.add_argument('--exec-ip', dest='exec_ip', type=str, default='127.0.0.1', help='Set server used for code execution output')
    execution.add_argument('--exec-share', dest='exec_share', type=str, default='C$',help='Set share used for code execution output')
    execution.add_argument('--exec-path', dest='exec_path', type=str, default='\\Windows\\Temp\\', help='Set path used for code execution output')
    execution.add_argument('--fileless', dest='fileless', action='store_true',help='Spawn SMB server for code execution output')
    execution.add_argument('--fileless_sharename', dest='fileless_sharename', type=str, default='', help=argparse.SUPPRESS)
    execution.add_argument('--no-output', dest='no_output', action='store_true', help='Execute command with no output')
    execution.add_argument('--slack', dest='slack', action='store_true',help='Send execution output to Slack (Config required)')

    target = enum_parser.add_argument_group("Scanning Options")
    target.add_argument('-random', dest='random', action='store_true', help='Randomize scanning order')
    target.add_argument('--ldap-srv', dest='ldap_srv', type=str, default='', help='Define LDAP server')
    enum_parser.add_argument(dest='target', nargs='+', help='target.txt, 127.0.0.0/24, range, "ldap", "eol"')

def enum_arg_mods(args, db_obj, logger):
    # Collect creds if not provided
    if not args.passwd and args.user and not args.hash:
        args.passwd = getpass("Enter password, or continue with null-value: ")

    elif args.cred_id and not args.user:
        enum_user = db_obj.extract_user(args.cred_id)
        args.user    = enum_user[0][0]
        args.passwd  = enum_user[0][1]
        args.hash    = enum_user[0][2]
        args.domain  = enum_user[0][3]

    # Gather target systems
    if args.target[0].startswith("{"):
        if args.cred_id:
            ldap_user = db_obj.extract_user(args.cred_id)
            username    = ldap_user[0][0]
            password    = ldap_user[0][1]
            hashes      = ldap_user[0][2]
            domain      = ldap_user[0][3]
        elif args.domain:
            username = args.user
            password = args.passwd
            hashes = args.hash
            domain = args.domain
        else:
            logger.warning("To use the LDAP feature, please select a valid credential ID or enter domain credentials")
            logger.warning("Insert credentials:\n\tactivereign db insert -u username -p Password123 -d domain.local")
            exit(0)


        if hashes:
            logger.status(['LDAP Authentication', '{}\{} (Password: None) (Hash: True)'.format(domain, username)])
        else:
            logger.status(['LDAP Authentication', '{}\{} (Password: {}*******) (Hash: False])'.format(domain, username, password[:1])])

        try:
            l = LdapCon(username, password, hashes, domain, args.ldap_srv, args.timeout)
            l.create_ldap_con()
            if not l:
                logger.status_fail(['LDAP Connection', 'Unable to create LDAP connection'])
                exit(1)
            logger.status_success(['LDAP Connection', 'Connection established (server: {}) (LDAPS: {})'.format(l.host, l.ldaps)])

            if args.target[0] == '{ldap}':
                args.target = list(l.computer_query(False, False).keys())
            elif args.target[0] == "{eol}":
                args.target = list(l.computer_query('eol', False).keys())
            logger.status_success(['LDAP Connection','{} computers collected'.format(len(args.target))])

        except Exception as e:
            if "invalidCredentials" in str(e):
                logger.fail(["LDAP Error", "Authentication failed"])
            else:
                logger.fail(["LDAP Error", str(e)])
            exit(1)
    else:
        args.target = ipparser(args.target[0])

    if "--threshold" not in argv:
        tmp = db_obj.extract_lockout(args.domain)
        if tmp:
            args.lockout_threshold = tmp
            logger.status(["Lockout Tracker", "Threshold Extracted from database: {}".format(str(tmp))])
        else:
            logger.status(["Lockout Tracker", "Using default lockout threshold: {}".format(str(args.lockout_threshold))])
    else:
        db_obj.update_domain(args.domain, args.lockout_threshold)
        logger.status(["Lockout Tracker", "Updating {} threshold in database to: {}".format(args.domain, str(args.lockout_threshold))])

    if args.hash:
        logger.status(['Enum Authentication', '{}\{} (Password: None) (Hash: True)'.format(args.domain, args.user)])
    else:
        logger.status(['Enum Authentication', '{}\{} (Password: {}****) (Hash: False)'.format(args.domain, args.user, args.passwd[:1])])
    if 'l' in locals():
        l.close()
    return args
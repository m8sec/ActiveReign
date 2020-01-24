import os
import argparse
from sys import argv, exit
from getpass import getpass
from ipparser import ipparser

from ar3.core.ldap import LdapCon
from ar3.modules import list_modules
from ar3.helpers.misc import file_exists
from ar3.modules import get_module_resources

def enum_args(sub_parser):
    enum_parser = sub_parser.add_parser("enum", help='- System enumeration & Module execution')

    if "-L" in argv:
        list_modules()
        exit(0)
    enum_parser.add_argument('-t', dest='timeout', type=int, default=12,help='Connection timeout')
    enum_parser.add_argument('--refresh', dest="refresh", action='store_true', help="Download/update PowerShell scripts")
    enum_parser.add_argument('--gen-relay-list', dest='gen_relay_list', type=str, default='', help='Create a file of all hosts that dont require SMB signing')

    auth = enum_parser.add_argument_group("Host Authentication")
    auth.add_argument('-u', dest='user', type=str, default='', required=False,help='Set username (Default=null)')

    auth_pwd = auth.add_mutually_exclusive_group(required=False)
    auth_pwd.add_argument('-H', '-hashes', dest='hash', type=str, default='', help='Use Hash for authentication')
    auth_pwd.add_argument('-p', dest='passwd', type=str, default='', help='Set password (Default=null)')

    auth.add_argument('-id', dest='cred_id', type=int, help='Use creds from db for ldap queries/enumeration')
    auth.add_argument('-d', dest='domain', type=str, default='', help='Set domain (Default=null)')
    auth.add_argument('--local-auth', dest='local_auth', action='store_true', help='Authenticate to target host, no domain')
    auth.add_argument('--threshold', dest='lockout_threshold', type=int, default=3,help='Domain/System Lockout Threshold ''(Exits 1 attempt before lockout)')

    enum = enum_parser.add_argument_group("Enumerating Options")
    enum.add_argument('--pass-pol', dest="passpol", action='store_true', help="Enumerate password policy")
    enum.add_argument('--loggedon', dest='loggedon', action='store_true', help='Enumerate logged on users')
    enum.add_argument('--sessions', dest='sessions', action='store_true', help='Enumerate active sessions')
    enum.add_argument('--services', dest='list_services', action='store_true', help='List services & status')
    enum.add_argument('-s', '--sharefinder', dest="sharefinder", action='store_true',help="Find open file shares & check access")

    creds = enum_parser.add_argument_group("Gathering Credentials")
    creds.add_argument('--sam', dest='sam', action='store_true', help='Dump local SAM db')
    creds.add_argument('--lsa', dest='lsa', action='store_true', help='Extract LSA Secrets')
    creds.add_argument('--ntds', dest='ntds', action='store_true', help='Extract NTDS.dit file')
    creds.add_argument('--use-vss', action='store_true', default=False, help='Use the VSS method insead of default DRSUAPI')

    wmi = enum_parser.add_argument_group("WMI Query")
    wmi.add_argument('--tasklist', dest='list_processes', action='store_true', help='Show running processes')
    wmi.add_argument('--local-groups', dest='local_groups', action='store_true', help='List system local groups')
    wmi.add_argument('--local-members', dest='local_members', type=str, default='', help='List local group members')
    wmi.add_argument('--wmi', dest='wmi_query', type=str, default='', help='Execute WMI query')
    wmi.add_argument('--wmi-namespace', dest='wmi_namespace', type=str, default='root\\cimv2', help='WMI namespace (Default: root\\cimv2)')

    modules = enum_parser.add_argument_group("Module Execution")
    modules.add_argument('-M', dest='module', type=str, default='', help='Use AR3 module')
    modules.add_argument('-o', dest='module_args', type=str, default='', help='Provide AR3 module arguments')
    modules.add_argument('-L', dest='list_modules', type=str, default='', help='List all available modules')
    modules.add_argument('--reload', dest='module_reload', action='store_true', help='ReDownload module resources')

    spider = enum_parser.add_argument_group("Spidering")
    spider.add_argument('--spider', dest='spider', action='store_true',help='Crawl file share and look for sensitive info')
    spider.add_argument('--depth', dest='max_depth', type=int, default=5, help='Set scan depth (Default: 3)')
    spider.add_argument('--share', dest='share', type=str, default='', help='Define network share to scan: \'C$\'')
    spider.add_argument('--path', dest='start_path', type=str, default='/', help='Define starting path for share: \'/Windows/Temp/\'')
    spider.add_argument('--filename', dest="filename_only", action='store_true', help="Scan Filenames & extensions only")

    execution = enum_parser.add_argument_group("Command Execution")
    ps1exec = execution.add_mutually_exclusive_group(required=False)
    ps1exec.add_argument('-x', dest='execute', type=str, default='', help='Command to execute on remote server')
    ps1exec.add_argument('-X', dest='ps_execute', type=str, default='', help='Execute command with PowerShell')

    execution.add_argument('--force-ps32', dest='force_ps32', action='store_true',help='Run PowerShell command in a 32-bit process')
    execution.add_argument('--no-obfs', dest='no_obfs', action='store_true', help='Do not obfuscate PowerShell commands')

    execution.add_argument('--exec-method', dest='exec_method', choices=['wmiexec', 'smbexec','atexec', 'winrm'], default='wmiexec',help='Code execution method {wmiexec, smbexec, atexec, winrm}')
    execution.add_argument('--exec-ip', dest='exec_ip', type=str, default='127.0.0.1', help='Set server used for code execution output')
    execution.add_argument('--exec-share', dest='exec_share', type=str, default='C$',help='Set share used for code execution output')
    execution.add_argument('--exec-path', dest='exec_path', type=str, default='\\Windows\\Temp\\', help='Set path used for code execution output')
    execution.add_argument('--fileless', dest='fileless', action='store_true',help='Spawn SMB server for code execution output')
    execution.add_argument('--fileless_sharename', dest='fileless_sharename', type=str, default='', help=argparse.SUPPRESS)
    execution.add_argument('--no-output', dest='no_output', action='store_true', help='Execute command with no output')
    execution.add_argument('--slack', dest='slack', action='store_true',help='Send execution output to Slack (Config required)')

    target = enum_parser.add_argument_group("Target Options")
    targets = target.add_mutually_exclusive_group(required=True)
    targets.add_argument(dest='target', nargs='?', help='Positional argument, Accepts: target.txt, 127.0.0.0/24, ranges, 192.168.1.1')
    targets.add_argument('--ldap', dest='ldap', action='store_true', help='Use LDAP to target all domain systems')
    targets.add_argument('--eol', dest='eol', action='store_true', help='Use LDAP to target end-of-life systems on the domain')
    target.add_argument('--ldap-srv', dest='ldap_srv', type=str, default='', help='Define LDAP server (Optional)')

def enum_arg_mods(args, db_obj, loggers):
    logger  = loggers['console']
    context = argparse.Namespace(
         mode       = args.mode,
         timeout    = args.timeout,
         local_auth = False,
         debug      = args.debug,
         user       = False,
         passwd     = False,
         hash       = False,
         domain     = False,
        )

    # Check for user creds in db, QoL addition
    cred_id = db_obj.extract_credID(args.user, args.domain, args.passwd, args.hash)
    if cred_id:
        logger.status(['Credentials Saved', 'Next time try: -id {}'.format(str(cred_id))])

    # ReDownload module resources
    if args.module_reload:
        logger.status('Reloading module resources...')
        get_module_resources()
        logger.status_success('Scripts updated at: {}'.format(os.path.join(os.path.expanduser('~'), '.ar3', 'scripts')))
        exit(0)

    # Ask user for creds if user present and no password
    if not args.passwd and args.user and not args.hash:
        args.passwd = getpass("Enter password, or continue with null-value: ")

    # Cred ID present & no user/pass provided, for us in enumeration
    elif args.cred_id and "-u" not in argv:
        enum_user = db_obj.extract_user(args.cred_id)
        args.user    = enum_user[0][0]
        args.passwd  = enum_user[0][1]
        args.hash    = enum_user[0][2]
        args.domain  = enum_user[0][3]

    # Gather target systems using ldap
    if args.ldap or args.eol:
        if args.cred_id:
            ldap_user = db_obj.extract_user(args.cred_id)
            context.user    = ldap_user[0][0]
            context.passwd  = ldap_user[0][1]
            context.hash    = ldap_user[0][2]
            context.domain  = ldap_user[0][3]

        elif args.domain and args.user:
            context.user    = args.user
            context.passwd  = args.passwd
            context.hash    = args.hash
            context.domain  = args.domain


        else:
            logger.warning("To use the LDAP feature, please select a valid credential ID or enter domain credentials")
            logger.warning("Insert credentials:\n\tactivereign db insert -u username -p Password123 -d domain.local")
            exit(0)

        if context.hash:
            logger.status(['LDAP Authentication', '{}\{} (Password: None) (Hash: True)'.format(context.domain, context.user)])
        else:
            logger.status(['LDAP Authentication', '{}\{} (Password: {}*******) (Hash: False)'.format(context.domain, context.user, context.passwd[:1])])

        try:
            l = LdapCon(context, loggers, args.ldap_srv, db_obj)
            l.create_ldap_con()
            if not l:
                logger.status_fail(['LDAP Connection', 'Unable to create LDAP connection'])
                exit(1)
            logger.status_success(['LDAP Connection', 'Connection established (server: {}) (LDAPS: {})'.format(l.host, l.ldaps)])

            if args.ldap:
                args.target = list(l.computer_query(False, []).keys())
            elif args.eol:
                args.target = list(l.computer_query('eol', []).keys())
            logger.status_success(['LDAP Connection','{} computers collected'.format(len(args.target))])

        except Exception as e:
            if "invalidCredentials" in str(e):
                logger.fail(["LDAP Error", "Authentication failed"])
            else:
                logger.fail(["LDAP Error", str(e)])
            exit(1)
    else:
        args.target = ipparser(args.target)

    if "--threshold" not in argv:
        tmp = db_obj.extract_lockout(args.domain)
        if tmp:
            args.lockout_threshold = tmp
            logger.status(["Lockout Tracker", "Threshold extracted from database: {}".format(str(tmp))])
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
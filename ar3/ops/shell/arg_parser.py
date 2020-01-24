import argparse
from getpass import getpass

def shell_args(sub_parser):
    # Create Subparser
    shell_parser = sub_parser.add_parser("shell", help='- Spawn emulated shell on system')

    # Domain
    shell_domain = shell_parser.add_mutually_exclusive_group(required=False)
    shell_domain.add_argument('-t', dest='timeout', type=int, default=5,help='Connection timeout')
    shell_domain.add_argument('-d', dest='domain', type=str, default='', help='Set domain (Default=null)')
    shell_domain.add_argument('--local-auth', dest='local_auth', action='store_true', help='Authenticate to target host, no domain')
    shell_parser.add_argument('-id', dest='cred_id', type=int, help='Use creds from db for shell access')
    shell_parser.add_argument('-u', dest='user', type=str, default='', help='Admin Username')

    shell_pwd = shell_parser.add_mutually_exclusive_group(required=False)
    shell_pwd.add_argument('-H','-hashes', dest='hash', type=str, default='', help='Use Hash for authentication')
    shell_pwd.add_argument('-p', dest='passwd', type=str, default='', help='Set password (Default=null)')

    execution = shell_parser.add_argument_group("Command Execution")
    execution.add_argument('--exec-method', dest='exec_method', type=str, default='wmiexec',help='Code execution method {wmiexec, smbexec}')
    execution.add_argument('--exec-ip', dest='exec_ip', type=str, default='127.0.0.1',help='Set server used for code execution output')
    execution.add_argument('--exec-share', dest='exec_share', type=str, default='C$',help='Set share used for code execution output')
    execution.add_argument('--exec-path', dest='exec_path', type=str, default='\\Windows\\Temp\\',help='Set path used for code execution output')
    execution.add_argument('--fileless', dest='fileless', action='store_true',help='Spawn SMB server for code execution output')
    # Hidden Args: Required for execution methods to work but not applicable to the operational mode
    execution.add_argument('--ps_execute', dest='ps_execute', action='store_true',help=argparse.SUPPRESS)
    execution.add_argument('--fileless_sharename', dest='fileless_sharename', type=str, default='',help=argparse.SUPPRESS)
    execution.add_argument('--no-output', dest='no_output', action='store_true', help=argparse.SUPPRESS)
    execution.add_argument('--slack', dest='slack', action='store_true',  help=argparse.SUPPRESS)

    shell_parser.add_argument(dest='target', nargs='+', help='System to generate simulated shell')

def shell_arg_mods(args, db_obj, loggers):
    if args.user and not args.passwd and not args.hash:
        # Get password if not provided
        args.passwd = getpass("Enter password, or continue with null-value: ")

    if args.cred_id and not args.user:
        enum_user = db_obj.extract_user(args.cred_id)
        if enum_user:
            args.user   = enum_user[0][0]
            args.passwd = enum_user[0][1]
            args.hash   = enum_user[0][2]
            args.domain = enum_user[0][3]
        else:
            loggers['console'].fail("Unable to gather credentials from db, check workspace and try again")
            exit(1)
    args.target = args.target[0]
    if args.hash:
        loggers['console'].status(['Shell Authentication: {}\{} (Password: None) (Hash: True)'.format(args.domain, args.user)])
    else:
        loggers['console'].status(['Shell Authentication: {}\{} (Password: {}****) (Hash: False)'.format(args.domain, args.user, args.passwd[:1])])
    return args
from sys import argv
from os import path
from ipparser import ipparser

from ar3.core.ldap import LdapCon


def file_exists(parser, filename):
    # Used with argparse to check if input files exists
    if not path.exists(filename):
        parser.error("Input file not found: {}".format(filename))
    return [x.strip() for x in open(filename)]

def spray_args(sub_parser):
    # Create Subparser
    spray_parser = sub_parser.add_parser("spray", help='- Domain password spray or brute force')

    # Output / Display Options
    spray_parser.add_argument('-t', dest='timeout', type=int, default=5,help='Wait time for recursive thread to find files in dir')

    # Method
    spray_parser.add_argument('-m', '--spray-method', dest="method", type=str, default='SMB', help="Spray Method {SMB, LDAP} (Default: SMB)")

    # User
    sp_user = spray_parser.add_mutually_exclusive_group()
    sp_user.add_argument('-u', dest='user', type=str, action='append', help='User to spray {account name, ldap}')
    sp_user.add_argument('-U', dest='user', default=False, type=lambda x: file_exists(sub_parser, x), help='User file to spray {Users.txt}')

    # Password
    sp_pwd = spray_parser.add_mutually_exclusive_group(required=True)
    sp_pwd.add_argument('-p', dest='passwd', action='append', default=[], help='Single password')
    sp_pwd.add_argument('-P', dest='passwd', default='', type=lambda x: file_exists(sub_parser, x), help='Password file {pass.txt}')
    sp_pwd.add_argument('-x', dest="user_as_pass", action='store_true', help="Set username as password")
    sp_pwd.add_argument('-H','-hashes', dest='hash', type=str, default='', help='Use Hash for authentication')

    # Domain
    #spray_domain = spray_parser.add_mutually_exclusive_group(required=False)
    spray_parser.add_argument('-d', dest='domain', type=str, default='', help='Set domain')
    spray_parser.add_argument('--local-auth', dest='local_auth', action='store_true', help='Authenticat to target host, no domain')

    # Timing options
    spray_parser.add_argument('-j', dest='jitter', type=float, default=0, help='jitter (sec)')
    spray_parser.add_argument('--ldap-srv', dest='ldap_srv', type=str, default='', help='Define LDAP server')
    spray_parser.add_argument(dest='target', nargs='+', help='{target.txt, 127.0.0.0/24, range, ldap, eol}')

    # ldap Authentication to collect users and/or targets
    spray_parser.add_argument('-id', dest='cred_id', type=int, help='Use user id from db for LDAP queries')
    spray_parser.add_argument('--force-all', dest="force_all", action='store_true', help="Spray all users, regardless of BadPwd count")
    spray_parser.add_argument('--threshold', dest='default_threshold', type=int, default=3, help='Set lockout threshold, if failed to aquire from domain (default: 3')


# noinspection PyInterpreter,PyInterpreter
def spray_arg_mods(args, db_obj, logger):
        if args.user_as_pass:
            args.passwd.append(0)

        if args.hash:
            args.passwd = ['']

        if args.method.lower() == 'ldap' and args.local_auth:
            logger.warning('Cannot use LDAP spray method with local authentication')
            exit(0)

        if args.target[0] != "{ldap}":
            args.target = ipparser(args.target[0])


        if "{ldap}" in argv:
            if not args.cred_id:
                logger.warning("To use this feature, please choose a cred id from the database")
                logger.warning("Insert credentials:\r\n     activereign db insert -u username -p Password123 -d domain.local")
                exit(0)

            # Extract creds from db for Ldap query
            ldap_user = db_obj.extract_user(args.cred_id)
            if ldap_user:
                username = ldap_user[0][0]
                password = ldap_user[0][1]
                hashes   = ldap_user[0][2]
                domain   = ldap_user[0][3]
                logger.debug('Using {}\{}:{} to perform ldap queries'.format(domain, username,password))

                if hashes:
                    logger.status(['Executing LDAP with:', '{}\{}'.format(domain, username), '\t[Hash=True]'])
                else:
                    logger.status(['Executing LDAP with:', '{}\{}'.format(domain, username),'\t[Password: {}*******]'.format(password[:2])])

                try:
                    # Define ldap server to not deal with lockout/replication issues
                    if args.ldap_srv:
                        l = LdapCon(username, password, hashes, domain, args.ldap_srv, args.timeout)
                    elif args.user[0] == 'ldap' and args.target[0] not in ['ldap', 'eol']:
                        l = LdapCon(username, password, hashes, domain, args.target[0], args.timeout)
                    else:
                        l = LdapCon(username, password, hashes, domain, '', args.timeout)
                    l.create_ldap_con()
                    if not l:
                        logger.fail('Unable to create LDAP connection')
                        exit(1)
                    logger.success("LDAP connection established (server: {}) (LDAPS: {})".format(l.host, l.ldaps))

                    ########################################
                    # Get users via LDAP
                    ########################################
                    if args.user[0] == '{ldap}':
                        tmp_users = l.user_query('active', False)
                        if args.force_all:
                            # Force spray on all users in domain - not recommended
                            args.user = tmp_users.keys()
                            try:
                                args.user.remove(username)
                                logger.success2("Removed User: {} (Query User)".format(username))
                            except:
                                pass
                            logger.success('{} users collected'.format(len(args.user)))

                        else:
                            users = []
                            # Check BadPwd Limit vs Lockout Threshold
                            try:
                                tmp = l.domain_query(False)
                                lockout_threshold = int(tmp[list(tmp.keys())[0]]['lockoutThreshold'])
                                logger.success("Domain lockout threshold detected: {}\t Logon_Server: {}".format(lockout_threshold, l.host))
                            except:
                                logger.fail('Lockout threshold failed, using default threshold of {}'.format(args.default_threshold))
                                lockout_threshold=args.default_threshold

                            # Compare and create user list
                            for user, data in tmp_users.items():
                                try:

                                    # Remove query user from list
                                    if user.lower() == username.lower():
                                        logger.success2("Removed User: {} (Query User)".format(username))
                                    # Compare badpwd count + create new list
                                    if int(data['badPwdCount']) < (lockout_threshold - 1):
                                        users.append(user)
                                    else:
                                        logger.success2("Removed User: {} (BadPwd: {})".format(user, data['badPwdCount']))
                                except:
                                    # no badPwdCount value exists
                                    users.append(user)

                            args.user = users
                            logger.success('{}/{} users collected'.format(len(args.user), len(tmp_users)))

                    ########################################
                    # get targets via ldap
                    ########################################
                    if args.target[0] == '{ldap}':
                        args.target = list(l.computer_query(False, False).keys())
                        logger.success('{} computers collected'.format(len(args.target)))

                    l.close()
                except Exception as e:
                    logger.fail("Ldap Connection Error: {}".format(str(e)))
                    exit(1)
            else:
                logger.fail("Unable to gather creds from db, try again")
                exit(0)
        return args
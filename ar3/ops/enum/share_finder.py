from ar3.logger import highlight

def share_finder(con, args, loggers, target):
    valid_shares = []
    target_shares = {}

    try:
        target_shares = share_perms(con)
        for share, data in target_shares.items():

            if data['read'] == 'READ' or data['write'] == 'WRITE':
                loggers['console'].info([con.host, con.ip, "SHAREFINDER", "\\\\{}\\{}".format(con.host, share), highlight("{:<5}{:<10}".format(data['read'],data['write'])), data['description']])
            else:
                loggers['console'].info([con.host, con.ip, "SHAREFINDER", "\\\\{}\\{}".format(con.host, share),highlight("{:<5}{:<10}".format(data['read'], data['write'])), data['description']])

            #Log all shares to enum.csv
            loggers[args.mode].info("ShareFinder\t{}\t{}\t\\\\{}\\{}\t{}\t{}".format(target, args.user, target,share, data['read'], data['write'], data['description']))

            if data['read'] == 'READ':
                valid_shares.append(str(share))
    except Exception as e:
        loggers['console'].debug(["\\\\{}".format(target), target_shares, str(e)])
    return valid_shares

def share_perms(con):
    temp = {}
    try:
        for share in con.list_shares():
            name = share['shi1_netname'][:-1]
            desc = share['shi1_remark']

            temp[name] = {
                            'description' : desc.strip('\x00'),
                            'read' : '',
                            'write': ''
                        }

            if con.read_perm(name):
                temp[name]['read'] = 'READ'

            if con.write_perm(name):
                temp[name]['write'] = 'WRITE'

        return temp
    except Exception as e:
        return str(e)
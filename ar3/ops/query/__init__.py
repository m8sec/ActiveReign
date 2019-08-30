from socket import gethostbyname

from ar3.core.ldap import LdapCon

##################################################
# Resolve Domain/server name
##################################################
def resolve_host(domain):
    try:
        return gethostbyname(domain)
    except:
        return "n/a"

##################################################
# Argparse support functions
##################################################
def parse_attrs(attrs):
    if not attrs:
        return []
    else:
        return attrs.split(",")

##################################################
# Display/Format Query Data
##################################################
def print_keyValue(logger, k, v):
    logger.output(k)
    for x, y in v.items():
        logger.output("    {:<20} {}".format(x, y))

def format_data(logger, resp, lookup_type, query, attrs, resolve, verbose):
    # @TODO no verbose, aka debug=verbose
    for k, v in resp.items():
        if resolve:
            k = k + " - " + resolve_host(k)
        if verbose:
            print_keyValue(logger, k, v)
        elif attrs:
            print_keyValue(logger, k, v)
        elif lookup_type in ['user', 'users'] and query:
            print_keyValue(logger, k, v)
        elif lookup_type in ['domain', 'trust']:
            print_keyValue(logger, k, v)
        elif query == 'eol':
            logger.output("{}\t - {}".format(k, v['operatingSystem']))
        else:
            logger.output(k)

def main(args, config_obj, db_obj, loggers):
    logger = loggers['console']
    try:
        query = LdapCon(args.user, args.passwd, args.hash, args.domain, args.srv, args.timeout)
        query.create_ldap_con()
        logger.success('LDAP Connection', 'Connection established (server: {}) (LDAPS: {})'.format(query.host, query.ldaps))

        # Users
        if args.lookup_type in ['user', 'users']:
            resp = query.user_query(args.query, args.attrs)

        # Groups
        elif args.lookup_type in ['group', 'groups']:
            if args.query:
                resp = query.group_membership(args.query, args.attrs)
            else:
                resp = query.group_query(args.attrs)

        # Computers
        elif args.lookup_type in ['computer', 'computers']:
            resp = query.computer_query(args.query, args.attrs)

         # Domain
        elif args.lookup_type == 'domain':
            resp = query.domain_query(args.attrs)

        # Trust
        elif args.lookup_type == 'trust':
            resp = query.trust_query(args.attrs)

        # Custom
        elif args.lookup_type == 'custom':
            resp = query.custom_query(args.query, args.attrs)

        else:
            logger.fail("Invalid query operation:\n\t"
                        "activereign query {user|group|computer|domain|trust|custom} -u {user} -p {password} -d {domain} -s {server}\n\t"
                        "activereign query {user|group|computer|domain|trust|custom} -q {lookup value} -a {attributes} -id {credID}")
            return

        # Display results
        if args.lookup_type and resp:
            format_data(logger, resp, args.lookup_type, args.query, args.attrs, args.resolve, args.debug)

        query.close()
    except Exception as e:
        if "invalidCredentials" in str(e):
            logger.fail(["LDAP Error", "Authentication failed"])
        else:
            logger.fail(["LDAP Error", str(e)])
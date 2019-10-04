QUERIES = { 'users_active'        : '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
          'users_all'             : '(&(objectCategory=person)(objectClass=user))',
          'users_admin'           : '(&(objectCategory=person)(objectClass=user)(admincount=1))',
          'users_email_search'    : '(&(objectClass=user)(mail={}))',
          'users_account_search'  : '(&(objectClass=user)(sAMAccountName={}))',
          'cpu_all'               : '(&(objectClass=Computer))',
          'cpu_search'            : '(&(objectClass=Computer)(dNSHostName={}*))',
          'groups_all'            : '(&(objectCategory=group))',
          'group_members'         : '(&(objectCategory=group)(sAMAccountName={}))',
          'domain_policy'         : '(objectClass=domain)',
          'domain_trust'          : '(objectClass=trustedDomain)',
          'reversible_encryption' : '(&(objectClass=user)(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=128))',
          'pass_never_expire'     : '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))',
          'pass_not_required'     : '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))'
          }

ATTRIBUTES = { 'users' : [ 'Name', 'userPrincipalName', 'sAMAccountName', 'mail', 'company', 'department', 'mobile',
                           'telephoneNumber', 'badPwdCount', 'userWorkstations', 'manager', 'memberOf', 'manager',
                           'whenCreated', 'whenChanged', 'Comment', 'Info', 'Description','userAccountControl'],

            'cpu'   : ['dNSHostName', 'operatingSystem', 'operatingSystemVersion', 'operatingSystemServicePack', 'Description'],

            'groups': ['distinguishedName', 'cn', 'name', 'sAMAccountName', 'sAMAccountType', 'whenCreated', 'whenChanged', 'Description'],

            'domain': [ 'cn', 'dc', 'distinguishedName', 'lockOutObservationWindow', 'lockoutDuration',
                      'lockoutThreshold', 'maxPwdAge', 'minPwdAge', 'minPwdLength', 'pwdProperties',
                      'pwdHistoryLength', 'nextRid', 'dn',],

            'trust' : ['cn', 'flatName', 'name', 'objectClass', 'trustAttributes', 'trustDirection', 'trustPartner',
                     'trustType'],
            }
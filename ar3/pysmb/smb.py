from random import choice
from string import ascii_letters, digits
from smb.SMBConnection import SMBConnection

def smb_connect(server, user, passwd, domain, timeout):
    # Create SMB Connection using random client string
    client = ''.join([choice(ascii_letters + digits) for x in range(7)])
    con = SMBConnection(user, passwd, client, server, domain=domain, use_ntlm_v2=True, is_direct_tcp=True)
    con.connect(server, 445, timeout=timeout)
    return con
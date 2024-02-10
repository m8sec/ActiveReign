import re
import socket
from os import path
from requests import post
from random import choice
from base64 import b64encode
from datetime import datetime
from string import ascii_letters, digits
from urllib3 import disable_warnings, exceptions
disable_warnings(exceptions.InsecureRequestWarning)

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 53))
        x = s.getsockname()[0]
        s.close()
        return x
    except:
        return '127.0.0.1'

def get_ip(host):
    try:
        return socket.gethostbyname(host)
    except:
        return host

def gen_random_string(length=6):
    return''.join([choice(ascii_letters + digits) for x in range(length)])

def get_timestamp():
    return datetime.now().strftime('%m-%d-%Y %H:%M:%S')

def get_filestamp():
    # Timestamp formatted for filenames
    return datetime.now().strftime('%m-%d-%y-%H%M%S')

def slack_post(api_token, channel, data):
    header = {
                'Content-Type'  :   'application/json;charset=utf-8',
                'Authorization' :   'Bearer {}'.format(api_token),
             }
    post_data  = {
                    'as_user'   :   True,
                    'channel'   :   channel,
                    'text'      :   data
                 }
    return post('https://slack.com/api/chat.postMessage', verify=False, headers=header, json=post_data)

def ps_encoder(command):
    cmd =  b64encode(command)
    if len(cmd) >= 8191:
        return False
    return cmd

def validate_ntlm(data):
    allowed = re.compile("^[0-9a-f]{32}", re.IGNORECASE)
    if allowed.match(data):
        return True
    else:
        return False

def file_exists(parser, filename, contents=True):
    # Used with argparse to check if input files exists
    if not path.exists(filename):
        parser.error("Input file not found: {}".format(filename))
    if contents:
        # return file contents
        return [x.strip() for x in open(filename)]
    else:
        # return status
        return filename
import os
import importlib
from requests import get

import ar3

"""
A bit confusing how we set it up here but this will ensure 
"""
MODULES = {
    # 'Module Name/filename'  : {'Class Name', 'Source URL'}
    'example_module'          : {'Class' : 'ExampleModule'},
    'test_execution'          : {'Class' : 'TestExecution'},
    'process_hunter'          : {'Class' : 'ProcessHunter'},
    'invert_hunter'           : {'Class' : 'InvertHunter'},
    'user_hunter'             : {'Class' : 'UserHunter'},
    'get_netdomaincontroller' : {'Class' : 'GetNetDomainController'},
    'get_lockedaccounts'      : {'Class' : 'GetLockedAccounts'},
    'wifi_passwords'          : {'Class' : 'WifiPasswords'},
    'gpp_password'            : {'Class' : 'GPP_Password'},
    'kill_defender'           : {'Class' : 'KillDefender'},
    'wdigest'                 : {'Class' : 'Wdigest'},

    'mimikatz'                : {'Class' : 'InvokeMimikatz',
                                 'File'  : 'Invoke-Mimikatz.ps1',
                                 'URL'   : 'https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1'},

    'ironkatz'                : {'Class' : 'IronKatz',
                                 'File'  : 'Invoke-Ironkatz.ps1',
                                 'URL'   : 'https://raw.githubusercontent.com/m8r0wn/OffensiveDLR/master/Invoke-IronKatz.ps1'},

    'invoke_kerberoast'       : {'Class' : 'InvokeKerberoast',
                                 'File'  : 'Invoke-Kerberoast.ps1',
                                 'URL'   : 'https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1'},

    'invoke_vnc'              : {'Class' : 'InvokeVNC',
                                 'File'  : 'Invoke-Vnc.ps1',
                                 'URL'   : 'https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/management/Invoke-Vnc.ps1'},

    'procdump'                : {'Class' : 'ProcDump',
                                 'File'  : 'procdump.exe',
                                 'URL'   : 'https://live.sysinternals.com/procdump.exe'},
}

def list_modules():
    print(ar3.banner())
    print("       Active Modules")
    print("       \033[1;30m>>-------------------->\033[1;m")
    for mod in MODULES.keys():
        module_class = get_module_class(mod)
        class_obj = module_class()
        print('{:<6} {:<25} {}'.format(' ', mod, class_obj.description))
        for x in class_obj.args.keys():
            print('\033[1;30m{:32}   |_{}= {} (Required: {})\033[1;m'.format(' ',x, class_obj.args[x]['Description'], class_obj.args[x]['Required']))

def populate_mod_args(class_obj, module_args, logger):
    # -o 'SERVER=192.168.1.1,PROCESS=cmd.exe'
    arg_split = module_args.strip().split(',')

    # Populate module args
    for x in arg_split:
        if x:
            try:
                arg, value = x.split("=")
                class_obj.args[arg.upper()]['Value'] = value
            except:
                logger.fail("Unable to process arg: \"{}\"".format(x))
                exit(1)

        # Check for required arg
        for arg, data in class_obj.args.items():
            if data['Required'] and not data['Value']:
                logger.warning("{}: Missing required argument \"{}\"".format(class_obj.name, arg))
                exit(1)

def get_module_class(name):
    if name not in MODULES:
        raise Exception('Can not find module: {}'.format(name))
    cname = MODULES[name]['Class']
    modname = '.'.join([__name__, name])
    module = importlib.import_module(modname)
    return getattr(module, cname)

def get_module_resources():
    """
    Called by first_run to download script resources
    """
    for module, data in MODULES.items():
        if 'URL' in data.keys() :
            src = os.path.join(os.path.expanduser('~'), '.ar3', 'scripts', data['File'])
            if os.path.exists(src):
                os.remove(src)
            download_file(data['URL'], src)

def download_file(source, output):
    f = open(output, 'wb+')
    f.write(get(source, verify=False, timeout=5).content)
    f.close()

import importlib

import ar3

# List of all modules
_Modules = {
    # 'Module Name&filename'    : 'Class Name'
    'example_module'            : 'ExampleModule',
    'test_execution'            : 'TestExecution',
    'process_hunter'            : 'ProcessHunter',
    'invert_hunter'             : 'InvertHunter',
    'user_hunter'               : 'UserHunter',
    'get_netdomaincontroller'   : 'GetNetDomainController',
    'get_lockedaccounts'        : 'GetLockedAccounts',
    'wifi_passwords'            : 'WifiPasswords',
    'mimikatz'                  : 'InvokeMimikatz',
    'ironkatz'                  : 'IronKatz',
    'invoke_kerberoast'         : 'InvokeKerberoast',
}

def list_modules():
    print(ar3.banner())
    print("       Active Modules")
    print("       \033[1;30m>>-------------------->\033[1;m")
    for mod in _Modules.keys():
        module_class = get_module_class(mod)
        class_obj = module_class()
        print('{:<6} {:<25} {}'.format(' ', mod, class_obj.description))
        for x in class_obj.args.keys():
            print('\033[1;30m{:32}   |_{}= {} (Required: {})\033[1;m'.format(' ',x, class_obj.args[x]['Description'], class_obj.args[x]['Required']))

def populate_mod_args(class_obj, module_args, debug_arg, logger):
    # -o 'SERVER=192.168.1.1,PROCESS=cmd.exe'
    arg_split = module_args.strip().split(',')

    # Populate module args
    for x in arg_split:
        if x:
            try:
                arg, value = x.split("=")
                class_obj.args[arg]['Value'] = value
            except:
                logger.debug(debug_arg, "Unable to process arg: \"{}\"".format(x))

        # Check for required arg
        for arg, data in class_obj.args.items():
            if data['Required'] and not data['Value']:
                logger.WARNING("{}: Missing required argument \"{}\"".format(class_obj.name, arg), color='red')
                exit(1)

def get_module_class(name):
    if name not in _Modules:
        raise Exception('Can not find module: {}'.format(name))
    cname = _Modules[name]
    modname = '.'.join([__name__, name])
    module = importlib.import_module(modname)
    return getattr(module, cname)
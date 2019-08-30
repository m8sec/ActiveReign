from os import path
from sys import exit
from json import load

class ConfigLoader():
    def __init__(self):
        try:
            filepath = path.join(path.expanduser('~'), '.ar3')
            openFile = open('{}/config.json'.format(filepath), 'r')
            config = load(openFile)

            # Enum Settings
            self.PWN3D_MSG              = config['PWN3D_MSG']
            self.WORKSPACE              = config['WORKSPACE'].strip()
            self.SLACK_API              = config['SLACK_API_TOKEN']
            self.SLACK_CHANNEL          = config['SLACK_CHANNEL']
            self.RETRIEVE_TIMEOUT       = int(config['RETRIEVE_TIMEOUT'])
            self.PARSE_TIMEOUT          = int(config['PARSE_TIMEOUT'])
            self.MAX_CHAR               = int(config['MAX_CHAR'])
            self.MAX_FILE_SIZE          = int(config['MAX_FILE_SIZE'])
            self.WHITELIST_EXT          = config['WHITELIST_EXT']
            self.BLACKLIST_SHARE        = config['BLACKLIST_SHARE']
            self.BLACKLIST_SHAREFINDER  = config['BLACKLIST_SHAREFINDER']
            self.BLACKLIST_DIR          = config['BLACKLIST_DIR']
            self.KEY_WORDS              = config['KEY_WORDS']
            self.KEY_EXT                = config['KEY_EXT']
            self.XLSX_HEADERS           = config['XLSX_KEY_HEADERS']
            self.REGEX                  = config['REGEX']

            del(config)
            openFile.close()
            del openFile
        except Exception as e:
            print('Error parsing config file: {}'.format(e))
            exit(1)
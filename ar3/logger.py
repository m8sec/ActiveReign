import os
import sys
import logging

STYLE = {
    'None'      : '0',
    'bold'      : '1',
    'disable'   : '2',
    'underline' : '4',
    'blink'     : '5',
    'reverse'   : '7',
    'invisible' : '8',
    'strike'    : '9',
}

COLOR = {
    'None'  : '',
    'gray'  : ';30',
    'red'   : ';31',
    'green' : ';32',
    'yellow': ';33',
    'blue'  : ';34',
    'purple': ';35',
    'cyan'  : ';36',
    'white' : ';39',
}

HIGHLIGHT = {
    'None'  : '',
    'black' : ';40',
    'red'   : ';41',
    'green' : ';42',
    'orange': ';43',
    'blue'  : ';44',
    'purple': ';45',
    'cyan'  : ';46',
    'gray'  : ';47',
}

class AR3Adapter(logging.LoggerAdapter):
    __FORMATTER = {
        0: '{:<28}',  # Hostname
        1: '{:<16}',  # IP
        2: '{:<28} ', # Data label
        3: '{:<57}',  # os/data
        4: '{:<20}',  # Domain/data cont.
        5: '{:<17}',  # Signing
        6: '{:<14}',  # SMBv1
    }

    def __init__(self, logger_name='ar3'):
        self.logger = logging.getLogger(logger_name)

    def msg_spacing(self, data):
        if type(data) != list:
            return data
        tmp_data = ''
        spacer   = 0
        for value in data:
            try:
                if spacer == 2:
                    tmp_data += (self.__FORMATTER[spacer].format(highlight(value, color='blue', style='bold')) + ' ')
                else:
                    tmp_data += (self.__FORMATTER[spacer].format(value) + ' ')
            except Exception as e:
                tmp_data += '{} '.format(value)
            spacer += 1
        return tmp_data

    def process(self, msg, kwargs, color='blue', highlight='None', style='bold', bullet=''):
        # Backwards compatible with any logging methods not defined
        if not bullet:
            return msg, kwargs
        msg = self.msg_spacing(msg)
        return("{}{}\033[0m {}".format(code_gen(style, color, highlight), bullet, msg), kwargs)

    def info(self, msg, *args, **kwargs):
        msg, kwargs = self.process(msg, kwargs, color='blue', highlight='None', style='bold', bullet='[*]')
        self.logger.info(msg, *args, **kwargs)

    def output(self, msg, *args, **kwargs):
        self.logger.info(msg, *args, **kwargs)

    def success(self, msg, *args, **kwargs):
        msg, kwargs = self.process(msg, kwargs, color='green', highlight='None', style='bold', bullet='[+]')
        self.logger.info(msg, *args, **kwargs)

    def success2(self, msg, *args, **kwargs):
        msg, kwargs = self.process(msg, kwargs, color='yellow', highlight='None', style='bold', bullet='[+]')
        self.logger.info(msg, *args, **kwargs)

    def fail(self, msg, *args, **kwargs):
        msg, kwargs = self.process(msg, kwargs, color='red', highlight='None', style='bold', bullet='[-]')
        self.logger.info(msg, *args, **kwargs)

    def status(self, msg, *args, **kwargs):
        msg = self.msg_spacing(msg)
        msg = "{}[*] \033[1;30m{}\033[0m".format(code_gen('bold', 'blue', 'None'), msg)
        self.logger.info(msg, *args, **kwargs)

    def status_success(self, msg, *args, **kwargs):
        msg = self.msg_spacing(msg)
        msg = "{}[+] \033[1;30m{}\033[0m".format(code_gen('bold', 'green', 'None'), msg)
        self.logger.info(msg, *args, **kwargs)

    def status_success2(self, msg, *args, **kwargs):
        msg = self.msg_spacing(msg)
        msg = "{}[+] \033[1;30m{}\033[0m".format(code_gen('bold', 'yellow', 'None'), msg)
        self.logger.info(msg, *args, **kwargs)

    def status_fail(self, msg, *args, **kwargs):
        msg = self.msg_spacing(msg)
        msg = "{}[-] \033[1;30m{}\033[0m".format(code_gen('bold', 'red', 'None'), msg)
        self.logger.info(msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        msg, kwargs = self.process(msg, kwargs, color='purple', highlight='None', style='bold', bullet='[!]')
        self.logger.warning(msg, *args, **kwargs)


    def verbose(self, msg, *args, **kwargs):
        # @TODO At some point create a new log level "verbose" to print failure messages
        msg, kwargs = self.process(msg, kwargs, color='red', highlight='None', style='bold', bullet='[-]')
        self.logger.debug(msg, *args, **kwargs)


    def debug(self, msg, *args, **kwargs):
        msg, kwargs = self.process(msg, kwargs, color='cyan', highlight='None', style='bold', bullet='[D]')
        self.logger.debug(msg, *args, **kwargs)


def setup_logger(log_level=logging.INFO, logger_name='ar3'):
    formatter   = logging.Formatter('%(message)s')
    StreamHandler = logging.StreamHandler(sys.stdout)
    StreamHandler.setFormatter(formatter)
    logger = logging.getLogger(logger_name)
    logger.propagate = False
    logger.addHandler(StreamHandler)
    logger.setLevel(log_level)
    return AR3Adapter()


def setup_file_logger(workspace, log_name, log_level=logging.INFO, ext='.csv'):
    filename = setup_log_file(workspace, log_name, ext)
    formatter = logging.Formatter("%(message)s")
    fh = logging.FileHandler(filename)
    fh.setFormatter(formatter)
    logger = logging.getLogger(log_name)
    logger.addHandler(fh)
    logger.setLevel(log_level)
    return logger

def setup_outfile_logger(filename, log_name, log_level=logging.INFO):
    # User defined output files, not required under workspace context
    formatter = logging.Formatter("%(message)s")
    fh = logging.FileHandler(filename)
    fh.setFormatter(formatter)
    logger = logging.getLogger(log_name)
    logger.addHandler(fh)
    logger.setLevel(log_level)
    return logger

def setup_log_file(workspace, log_name, ext='.csv'):
    file_location = os.path.join(os.path.expanduser('~'), '.ar3', 'workspaces', workspace)
    if not os.path.exists(file_location):
        os.makedirs(file_location)
    return '{}/{}{}'.format(file_location, log_name, ext)


def print_args(args, logger):
    for k in args.__dict__:
        if args.__dict__[k] is not None:
            logger.debug(['args.{}'.format(k), '::: {}'.format(args.__dict__[k])])


def code_gen(style, color, highlight):
    """Outside logger adapter to be called from other places, aka highlighting"""
    code = '\033[0{}{}{}m'.format(STYLE[style], COLOR[color], HIGHLIGHT[highlight])
    return code


def highlight(data, color='blue', style='bold', highlight='None'):
    return "{}{}\033[0m".format(code_gen(style, color, highlight), data)
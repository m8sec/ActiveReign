import threading
from impacket.smb3structs import FILE_READ_DATA

from ar3.core.smb import SmbCon
from ar3.pysmb.smb import smb_connect
from ar3.helpers.remotefile import RemoteFile
from ar3.ops.enum.file_parser.parse_docx import parse_docx
from ar3.ops.enum.file_parser.parse_xlsx import parse_xlsx
from ar3.ops.enum.file_parser.parse_regex import parse_data

class ParserThread(threading.Thread):
    '''Parse file contents, on valid match returns dict:
    {
        'Parser': 'Regex',
        'ParserDetails': 'SSN',
        'LineCount': '39',
        'LineSample': 'SSN:xxx-xx-xxxx'
    }'''

    def __init__(self, config, db, args, loggers, file_data):
        threading.Thread.__init__(self)
        # Create SMB connection to parse file
        self.args    = args
        self.loggers = loggers
        self.db      = db

        self.logger   = loggers['console']
        self.filer    = loggers['spider']
        self.debug    = args.debug
        self.timeout  = args.timeout
        self._running = True

        self.user       = args.user
        self.passwd     = args.passwd
        self.hash       = args.hash
        self.domain     = args.domain
        self.local_auth = args.local_auth

        # Unpack data from search_thread queue
        self.ip         = file_data['ip']
        self.host       = file_data['host']
        self.share      = file_data['share']
        self.path       = file_data['path']
        self.filename   = file_data['filename']

        # Unpack configs
        self.filename_only  = args.filename_only
        self.regex          = config.REGEX
        self.keywords       = config.KEY_WORDS
        self.ext            = config.KEY_EXT
        self.xlsx_keywords  = config.XLSX_HEADERS
        self.max_size       = config.MAX_CHAR
        self.max_chars      = config.MAX_FILE_SIZE
        self.logger.debug("ParserThread Init: \\\\{}\\{}{}{}".format(self.ip, self.share, self.path.replace("/", "\\"), self.filename))


    def run(self):
        try:
            self.parse(self.ip, self.share, self.path, self.filename)
            return
        except Exception as e:
            self.logger.debug("ParserThread Err: \\\\{}\\{}{}{}\tFileParser:{}".format(self.ip, self.share, self.path.replace("/", "\\"), self.filename, str(e)))

    def stop(self):
        self._running = False

    def parse(self, server, share, path, filename):
        while self._running:
            # File Extension
            ext = file_extension(filename)
            if ext in self.ext:
                self.reporter('Extension', ext,'', '')
                return

            # Key Word in filename
            keyword = self.keyword_search(filename)
            if keyword in self.keywords:
                self.reporter('Keyword', keyword, '', '')
                return

            # Parse File Contents
            if not self.filename_only:
                ## Parse Excel (Uses pysmb, not hash auth)
                if ext == 'xlsx' and not self.hash:
                    # Create SMB connection using pysmb
                    con = smb_connect(server, self.user, self.passwd, self.domain, self.timeout)

                    result = parse_xlsx(self.xlsx_keywords, self.regex, self.max_size, self.max_chars, self.timeout, con, share, path, filename)
                    if result:
                        self.reporter(result['Parser'], result['ParserDetails'], result['LineCount'], result['LineSample'])
                        con.close()
                        return
                    con.close()

                ## Parse Word Docs (Uses pysmb, not hash auth)
                elif ext == 'docx' and not self.hash:
                    # Create SMB connection using pysmb
                    con = smb_connect(server, self.user, self.passwd, self.domain, self.timeout)

                    result = parse_docx(self.regex, self.max_chars, self.max_size, self.timeout, con, share, path, filename)
                    if result:
                        self.reporter(result['Parser'], result['ParserDetails'], result['LineCount'], result['LineSample'])
                        con.close()
                        return
                    con.close()

                ## Parse All other file types
                else:
                    # Create SMB connection using Impacket
                    smb_obj = SmbCon(self.args, self.loggers, server, self.db)
                    smb_obj.create_smb_con()

                    try:
                        reader = RemoteFile(smb_obj.con, path + filename, share, access=FILE_READ_DATA)
                        reader.open()
                        contents = reader.read(self.max_size)
                    except:
                        self.logger.debug("Failed to open file: {}".format(path + filename))
                        return

                    # Pass Contents to parser
                    result = parse_data(contents, self.regex, self.max_chars, filename)
                    if result:
                        self.reporter(result['Parser'], result['ParserDetails'], result['LineCount'], result['LineSample'])

                    # Close open reader object
                    reader.close()
                    del (reader)
                    smb_obj.close()
            return

    def keyword_search(self, filename):
        #Search for keywords in filename
        for word in self.keywords:
            if word in filename.lower():
                return word
        return False

    def reporter(self, search, search_detail, line_num, line_detail):
        full_path = "\\\\" + self.host + "\\" + self.share + self.path.replace("/", "\\") + self.filename
        # Used for gpp_password module & decryption:
        if search_detail == 'gpp_password':
            from ar3.modules.gpp_password import cpassword_parser
            cpassword_parser(self.loggers, self.host, self.ip, full_path, line_detail)
        # Write spider results to terminal and log
        else:
            self.filer.info("Spider\t{}\t{}\t{}".format(search, full_path, line_detail))
            line = "{:<10} : {}".format(search, full_path)
            if line_num:
                line += " (Line: {})".format(line_num)
            self.logger.success([self.host, self.ip, "SPIDER", line])
            if line_detail:
                self.logger.success([self.host, self.ip, "SPIDER", "{:<10} : {}".format("Details", line_detail.strip())])

def file_extension(filename):
    try:
        return filename.split('.')[-1].lower()
    except:
        return
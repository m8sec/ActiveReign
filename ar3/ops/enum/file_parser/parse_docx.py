from docx import Document

from ar3.pysmb.file_ops import get_fileobj, close_fileobj
from ar3.ops.enum.file_parser.parse_regex import regex_search

def parse_docx(regex, max_chars, max_size, timeout, con, share, path, filename):
    line_count = 1
    try:
        file_obj = get_fileobj(con, share, str(path), str(filename), max_size, timeout)
        doc = Document(file_obj)
        for para in doc.paragraphs:
            # Return on lookup
            search_data = regex_search(regex, max_chars, para.text, line_count, filename)
            if para.text != '' and search_data:
                close_fileobj(file_obj)
                return search_data
            line_count += 1
        # Close file obj
        close_fileobj(file_obj)
    except:
        pass
    return False
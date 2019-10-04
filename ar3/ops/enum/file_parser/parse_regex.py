from re import findall

def parse_data(contents, regex, max_chars, filename):
    # Get file data
    line_count = 1
    # Splitlines and look for regex matches
    for line in contents.splitlines():
        if line:
            # Parse line for sensitive information
            search_data = regex_search(regex, max_chars, line, line_count, filename)
            if search_data:
                # Return on first found match in file
                return search_data
        line_count += 1
    # Close & return on no match
    return  False

def regex_search(regex, max_chars, line, line_count, filename):
    # Function called by various modules to identify regex patters from text
    try:
        line = line[:max_chars].decode('UTF-8')
    except:
        line = line[:max_chars]
    # Begin regex lookup
    for key, value in regex.items():
        try:
            for x in findall(value, line):
                # Skip credit card lookup for pdf files (false positives)
                if key == 'Credit Card' and filename.endswith('pdf'):
                    pass
                elif key == 'Credit Card' and luhn_checksum(x) != 0:
                    pass
                else:
                    # return after one positive match in line
                    return { 'Parser': 'Regex',
                             'ParserDetails': key,
                             'LineCount': line_count,
                             'LineSample': """{}""".format(x)}#.replace("\"", "'")}
        except Exception as e:
            if "bytes-like object" in str(e):
                return False
    return False

def luhn_checksum(card_number):
    # Src: https://stackoverflow.com/questions/21079439/implementation-of-luhn-formula
    def digits_of(n):
        return [int(d) for d in str(n)]
    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = 0
    checksum += sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(d * 2))
    return checksum % 10
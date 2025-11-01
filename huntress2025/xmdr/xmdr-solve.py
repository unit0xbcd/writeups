#!/usr/bin/env python3
import re
from urllib.parse import unquote_plus, urlparse
from binascii import a2b_uu
from colorama import Fore, Style

# open urls from txt file

with open("output_file.txt", "r") as f:
    for line in f:
        line = line.strip()

# urldecode

        query = unquote_plus(urlparse(line).query)

# find the uuencoded payload

        payload = re.search(r'begin\s+664\s+-\r?\n([^\r\n]+)', query, re.I)

# uuendecode

        command = a2b_uu(payload.group(1)).decode('utf-8').strip()

# print 'em - colour for flag print

        if 'flag' in command:
            print(f"{Fore.LIGHTMAGENTA_EX}{command} {Style.RESET_ALL}")
        else:
            print(command)



#!/usr/bin/env python3

from struct import unpack
from datetime import datetime, timedelta
from sys import argv
from os import listdir
from re import sub

library = []

# open all the files we want - just the metadata $I files

trashfiles = [el for el in listdir('.') if el.startswith('$I')]
for entry in trashfiles:
	with open(entry, "rb") as file:
		
# grab header whole - avoid repeated seeks
		header = file.read(24)

# flag character position - first two bytes of file size field

		char = header[8:10].decode('utf-16le')
		
    
# deletion time

		bytetime = header[16:24]
		inttime = unpack('<Q', bytetime)[0]
		filetime = datetime(1601,1,1)+timedelta(seconds=inttime/1e7)
		
# chuck into the library

		library.append({'char': char, 'filetime': filetime})
		
# sort by our deletion time

library.sort(key=lambda x: x['filetime'])

#maybe flag ?

flag = ''.join(el['char'] for el in library)

# too much flag!

cleanflag = sub(r'(.)\1{2}', r'\1', flag).strip()

# just the right amount of flag

print(flag)


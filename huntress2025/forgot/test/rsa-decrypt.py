#!/usr/bin/env python3
from Crypto.PublicKey import RSA
k=RSA.import_key(open("private.pem","rb").read())
c=open("key.enc","rb").read()
m=pow(int.from_bytes(c,"big"),k.d,k.n)
open("key_raw.bin","wb").write(m.to_bytes((k.n.bit_length()+7)//8,"big"))


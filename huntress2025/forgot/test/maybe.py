#!/usr/bin/env python3
from Crypto.Cipher import AES
B=open("key_raw.bin","rb").read()   # 48 bytes
E=open("flag.enc","rb").read()

def printable_ratio(b):
    if not b: return 0
    good=sum(1 for x in b if 32<=x<127 or x in (9,10,13))
    return good/len(b)

def try_gcm(key,iv,ct,tag):
    try:
        return AES.new(key,AES.MODE_GCM,nonce=iv).decrypt_and_verify(ct,tag)
    except Exception:
        return None

def try_ctr(key,iv,ct):
    try:
        return AES.new(key,AES.MODE_CTR,nonce=iv).decrypt(ct)
    except Exception:
        return None

def try_block_modes(key,iv,ct):
    out=[]
    try: out.append(("CBC", AES.new(key,AES.MODE_CBC,iv).decrypt(ct)))
    except Exception: pass
    try: out.append(("CFB", AES.new(key,AES.MODE_CFB,iv).decrypt(ct)))
    except Exception: pass
    try: out.append(("OFB", AES.new(key,AES.MODE_OFB,iv).decrypt(ct)))
    except Exception: pass
    return out

# prepare ciphertext/tag candidates
cands=[]
if len(E)>16:
    cands.append(("end16", E[:-16], E[-16:]))
cands.append(("whole", E, None))
cands.append(("start16", E[16:], E[:16]))  # tag at start possibility
# main sweep
for keylen in (32,24,16):
    if keylen>=len(B): continue
    ivlen = len(B)-keylen
    key=B[:keylen]; iv=B[keylen:keylen+ivlen]
    print("TRY keylen",keylen,"ivlen",ivlen)
    for label,ct,tag in cands:
        # try GCM if tag present or try decrypt-only to inspect plaintext
        if tag is not None:
            pt=try_gcm(key,iv,ct,tag)
            if pt is not None:
                print("GCM SUCCESS",keylen,ivlen,label)
                print(pt.decode(errors="ignore"))
                raise SystemExit
            else:
                # try decrypt without verify (just to inspect)
                try:
                    p=AES.new(key,AES.MODE_GCM,nonce=iv).decrypt(ct)
                    pr=printable_ratio(p)
                    if b"flag{" in p or pr>0.6:
                        print("GCM-decrypt-only candidate",keylen,ivlen,label,"PR",pr)
                        print(p.decode(errors="ignore"))
                except Exception:
                    pass
        # CTR
        pt=try_ctr(key,iv,ct)
        if pt is not None:
            pr=printable_ratio(pt)
            if b"flag{" in pt or pr>0.6:
                print("CTR candidate",keylen,ivlen,label,"PR",pr)
                print(pt.decode(errors="ignore"))
                raise SystemExit
        # block modes if IV is 16
        if ivlen==16:
            for mname,mpt in try_block_modes(key,iv,ct):
                pr=printable_ratio(mpt)
                if b"flag{" in mpt or pr>0.6:
                    print(mname,"candidate",keylen,ivlen,label,"PR",pr)
                    print(mpt.decode(errors="ignore"))
                    raise SystemExit
print("done")


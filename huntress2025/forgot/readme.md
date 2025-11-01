# I Forgot

I Forgot is a forensics challenge from the Huntress CTF 2025. We are provided with a 1GB memory dump, an encrypted flag file as `flag.enc` and the following information.

<em>So.... bad news.

We got hit with ransomware.

And... worse news... we paid the ransom.

After the breach we FINALLY set up some sort of backup solution... it's not that good, but, it might save our bacon... because my VM crashed while I was trying to decrypt everything.

And perhaps the worst news... I forgot the decryption key.

Gosh, I have such bad memory!!</em>

Scanning with volatility shows a Windows 10 image. Based on the challenge description I was particularly interested in any open text files and any backup processes. First I listed the running processes and identified Notepad.exe

```
(tools) unit0xbcd@darkstar: vol -f memdump.dmp windows.pstree

<snip>
***** 1388      5920    Notepad.exe     0xdf07c45b70c0  6       -       1       False   2025-09-28 04:41:51.000000 UTC N/A      \Device\HarddiskVolume3\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2312.18.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe  -       -
****** 1628     1388    Notepad.exe     0xdf07c50d2080  17      -       1       False   2025-09-28 04:41:51.000000 UTC N/A      \Device\HarddiskVolume3\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2312.18.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe  -       -


```

I dumped the memory from pid `1388` and started looking for relevant information with `strings` and `less`. Very quickly I found some fragments of text that proved useful. I saved them to a temporary file until I thought I had everything I needed.

```
(tools) unit0xbcd@darkstar: vol -f memdump.dmp windows.memmap --pid 1388 --dump


ing 7-Zip (GUI): Right-click -> Open archive -> enter password ePDaACdOCwaMiYDG
2) Decrypt the AES key+IV:
   openssl pkeyutl -decrypt -inkey private.pem -in key.enc -out key_raw.bin -pkeyopt rsa_p
   
All your important files were encrypte

Your Files Has Been EncryptedY
openoneofthefollowinglinksinyourbrowsertodownloaddecryptor

INSTRUCTIONS_FOR_DECRYPTION.txt
DECRYPT_PRIVATE_KEY.zip

C:\Users\User\Desktop\INSTRUCTIONS_FOR_DECRYPTION.txt
C:\Users\User\Desktop\DECRYPT_PRIVATE_KEY.zip
```
<em>various text fragments that looked like they might be useful extracted from the noise </em>

This told me that my flag was encrypted with an AES varient that uses an IV and that the key and IV were RSA encrypted and stored inside a password protected zip file. I needed to find that zip file, assuming it was in memory. There was no copy of WinZip or 7Zip running to dump from, but the clue was in the challenge description.

<em>After the breach we FINALLY set up some sort of backup solution</em>

I figured it was likely the zip file would be in the memory for a backup process. First, to find it.

```
(tools) unit0xbcd@darkstar: vol -f memdump.dmp windows.pstree
<snip>
***** 2132      5920    BackupHelper.e  0xdf07c4733080  6       -       1       False   2025-09-28 04:41:51.000000 UTC  N/A     \Device\HarddiskVolume3\Users\User\Desktop\BackupHelper.exe  -       -```
```

Then to dump the pid 

```(tools) unit0xbcd@darkstar: vol -f memdump.dmp windows.memmap --pid 2132 --dump```

I usually use volatility to carve out files - but out of laziness I decided to try ```binwalk```. I could see at least one zip file, and asked binwalk to extract them.

```
(tools) unit0xbcd@darkstar: binwalk pid.2132.dmp 

------------------------------------------------------------------------------------------------------------------------
DECIMAL                            HEXADECIMAL                        DESCRIPTION
------------------------------------------------------------------------------------------------------------------------
16384                              0x4000                             ZIP archive, file count: 2, total size: 1938 
                                                                      bytes
5353472                            0x51B000                           Windows PE binary, machine type: Intel x86-64
6246144                            0x5F4F00                           SHA256 hash constants, little endian
9153744                            0x8BACD0                           CRC32 polynomial table, little endian
<snip>

(tools) unit0xbcd@darkstar: binwalk -e --dd='zip:zip'

```

It carved me a valid zip file and I extracted it using the password from the Notepad.exe fragment.

```
(tools) unit0xbcd@darkstar: file zip_4000.bin
zip_4000.bin: Zip archive data, made by v3.0 UNIX, extract using at least v2.0, last modified, last modified Sun, Sep 28 2025 00:35:48, uncompressed size 1708, method=deflate

(tools) unit0xbcd@darkstar: 7z e zip_4000.bin

ls

key.enc private.pem

```

With the RSA certificate and encrypted key, I could generate the AES key and IV I would need to decrypt the flag. I used the command from the Notepad.exe fragment - but I couldn't get it to work. I had taken ```openssl pkeyutl -decrypt -inkey private.pem -in key.enc -out key_raw.bin -pkeyopt rsa_p``` from the strings I had discovered but I was missing the rest of the line. I read the relevant ```openssl``` manpage to see what that truncated option was likely to be and realised I needed to know the RSA padding mode. I went back and did a quick grep for 'rsa_padding_mode' and found the rest of the command.

```
(tools) unit0xbcd@darkstar: openssl pkeyutl -decrypt -inkey private.pem -in key.enc -out key_raw.bin -pkeyopt rsa_padding_mode:oaepl

(tools) unit0xbcd@darkstar: ls -a key_raw.bin

-rw-r--r--. 1 unit0xbcd unit0xbcd   48 Oct 14 14:36 key_raw.bin

```

48 bytes made much more sense as that matched the length I needed for AES 256 CBC. I broke it up into 32 bytes for the key and 16 bytes for the IV and decrypted 'flag.enc' in cyberchef.

```
xxd -p -c 99 key_raw.bin | head -c 64 ;echo
289ea58a38549d5faf7a97a6dd19cdf2ddc0496a8a64f99a77c643529c94b804     # key

xxd -p -c 99 key_raw.bin | tail -c 33 ;echo
2c6a55b0a89141056517687a977305d6    # IV

```
[https://gchq.github.io/CyberChef/#recipe=AES_Decrypt](https://gchq.github.io/CyberChef/#recipe=AES_Decrypt(%7B'option':'Hex','string':'289EA58A38549D5FAF7A97A6DD19CDF2DDC0496A8A64F99A77C643529C94B804'%7D,%7B'option':'Hex','string':'2C6A55B0A89141056517687A977305D6'%7D,'CBC','Raw','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)&input=RwNUMGGti0%2BLDKlAtfdgVdqc0nxBbx1Bikmsn3mxOQ2EawsWYP0pcpC20T2j53HfG/s7xddK5rSSHuLRRSqwp%2BdcjoHJBuL9bgpXbJ2Vzel3d1aSsk2x90oJqlDsWCbph2Sv6E8%2BmACQ6KbVc%2B0Ih5aPJASQQACG4xSZNfSaJom5H38vAt7LOT9TSnutzp6jjkElRHs7cNk5pObJi5HD5192We3t/1UQ86uCQUqvLN1ClvSCdmmv0JN3sGwHWboUrwb0Tqh8L8twawfSWIhHOg)


```

=== CONFIDENTIAL RECOVERY ===
Note: This file contains the recovered data for decryption.
-----------------------------
FLAG:
flag{fa838fa9823e5d612b25001740faca31}
-----------------------------

```


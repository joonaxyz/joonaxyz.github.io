---
layout: post
title: "HackTheBox - Blunder"
author: "joona"
---
![](/images/blunder/header.jpg)
Pretty fun and straightforward Linux box. The initial foothold gave me some resistance, but
after that it's smooth sailing and the privilege escalation was really simple.<br/>
<br/>

## Nmap results
{% highlight plaintext %}
# Nmap 7.80 scan initiated Tue Jun  9 14:12:02 2020 as: nmap -p21,80 -A -T4 -oA nmap/blunder 10.10.10.191
Nmap scan report for 10.10.10.191
Host is up (0.053s latency).

PORT   STATE  SERVICE VERSION
21/tcp closed ftp
80/tcp open   http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: Blunder
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Blunder | A blunder of interesting facts
Aggressive OS guesses: HP P2000 G3 NAS device (91%), Linux 2.6.32 (90%), Infomir MAG-250 set-top box (90%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (90%), Netgear RAIDiator 4.2.21 (Linux 2.6.37) (90%), Linux 2.6.32 - 3.13 (89%), Linux 3.3 (89%), Linux 3.7 (89%), Ubiquiti AirOS 5.5.9 (89%), Ubiquiti Pico Station WAP (AirOS 5.2.6) (88%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   52.38 ms 10.10.14.1
2   52.88 ms 10.10.10.191

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jun  9 14:12:14 2020 -- 1 IP address (1 host up) scanned in 12.76 seconds
{% endhighlight %}

<br/>
## Website enumeration and initial foothold
{% highlight plaintext %}gobuster dir -u 10.10.10.191 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt -t 20{% endhighlight %}
With gobuster we find `todo.txt` where a user `fergie` is mentioned.<br/>

![](/images/blunder/todo.jpg)<br/>

We also find a `Bludit CMS` login page at `http://10.10.10.191/admin/`.
Inside the page source we can see that the Bludit version installed is `3.9.2`.

![](/images/blunder/version.jpg)<br/>

Googling exploits for this version we find a [Bruteforce Mitigation Bypass](https://rastating.github.io/bludit-brute-force-mitigation-bypass/) exploit. <br/>
The version 3.9.2 and versions prior to that are vulnerable to a bypass of the anti-bruteforce mechanism.<br/>
This is achieved by changing the HTTP headers to fake the source of the login requests.<br/>

I tried using multiple different wordlists to bruteforce the login but had no luck.<br/>

The index page has short articles instead of Lorem ipsum, so I decided to create a wordlist with `CeWL` consisting of words inside the articles.<br/>
`cewl 10.10.10.191 > passlist.txt`<br/>
We get a passlist.txt with about 350 words.

I used the [PoC code](https://raw.githubusercontent.com/musyoka101/Bludit-CMS-Version-3.9.2-Brute-Force-Protection-Bypass-script/master/bruteforce.py)
mentioned in Rastating's blogpost to bruteforce the login.<br/>
We need to edit the following variables:<br/>

![](/images/blunder/brute.jpg)<br/><br/>


After firing this script at our target we receive a valid password for user fergus.
We can now use these credentials to log in.

![](/images/blunder/dashboard.jpg)<br/>
<br/>

Now that we have valid credentials we can use exploit [CVE-2019-16113](https://www.cvedetails.com/cve/CVE-2019-16113/)
to execute remote code and receive a reverse shell.<br/>
There's a Metasploit module for this (*exploit/linux/http/bludit_upload_images_exec*):

![](/images/blunder/cve201916113.jpg)<br/>

After running this we get a reverse meterpreter shell as user `www-data`.<br/>
<br/>

## Privilege escalation
The box has home folders for users `hugo` and `shaun`.<br/>
After doing some manual enumeration with our www-data shell, I discovered that
there's an another Bludit version (3.10.0a) folder in `/var/www`-directory.<br/>


According to [Bludit forums](https://forum.bludit.org/viewtopic.php?t=767), there should be a
password in `/bl-content/databases/users.php`.<br/>
There's a SHA1 hashed password for user Hugo in `/var/www/bludit-3.10.0a/bl-content/databases/user.php`<br/>

![](/images/blunder/usersphp.jpg)<br/>

I used [md5decrypt.net](https://md5decrypt.net/en/Sha1/) to decrypt the SHA-1.<br/><br/>

Now we can spawn a TTY Shell so we can switch to user hugo (`su hugo`):<br/>
`python -c 'import pty; pty.spawn("/bin/sh")'`

Running `sudo -l` to see if we can do anything as another user gives us interesting results.<br/>
![](/images/blunder/sudo.jpg)<br/>

We can run `/bin/bash` as everyone except root. <br/>


There's a [security bypass](https://www.exploit-db.com/exploits/47502) for this if the installed
sudo version is 1.8.27 or earlier. Checking the version with `sudo -V` we see that the version
is `1.8.25p1`.<br/>

If we run `sudo -u#-1 /bin/bash` we get a shell as user root and get the root flag. Easy!<br/>
-u#-1 returns 0 which is root's user id.

<br/>
Thank you for reading!

{% highlight plaintext %}
{% endhighlight %}

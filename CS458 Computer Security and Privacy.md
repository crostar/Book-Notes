# CS458 Computer Security and Privacy



## Module 1. Introduction to Computer Security & Privacy

### What is Security?

- **Security** generally means three things
  - **confidentiality**: Access to systems or data is limited to authorized parties
  - **Integrity**: When you receive data, you get the right data
  - **Availability**: The system or data is there when you want it
- A computing system is said to be secure if it has all three properties
- A secure system is **reliable** in some aspects

### What is Privacy?

- **Informational self-determination**: **you** get to **control** information **about you**

### What are the adversaries/attackers?

> If there is only one thing you should take away from this course, that is "Think as an attacker".

- Murphy: anything that could go wrong will go wrong (**Random error**)
- Amateurs / "Script kiddies" / Crackers
- Organized crime
- Government "cyberwarriors"
- Terrorists

### Some terminology

- **Assets**: Things we might want to protect, such as **hardware, software, data**
- **Vulnerabilities**: Weaknesses in a system that may be able to be **exploited**

- **Threats**: A loss or harm that might befall a system

When designing a system, we need to state thread model: whom do we want to prevent from doing what

- **Attack**: An action which **exploits** a **vulnerability** to **execute** a **threat**

- **Control**/**Defense**: **control** a **vulnerability** to prevent an **attack** and **defend** against a **threat**

  - Prevent it: prevent the attack
  - Deter it: make the attack harder or more expensive
  - Deflect it: make yourself less attractive to attacker
  - Detect it: notice that attack is occurring (or has occurred)

  - Recover from it: mitigate the effects of the attack

### How secure should we make it?

- Principle of Easiest Penetration: A system is only as strong as its weakest link
- Principle of Adequate Protection: Security is economics

### Defense of computer systems

- Cryptography: protecting data by making it unreadable to an attacker
- Software controls
  - Passwords and other forms of access control
  - OS separate users' actions from each other
  - Virus scanners watch from some kinds of malware
- Hardware controls
  - Fingerprint readers / Smart tokens / Firewalls
  - Trusted Execution Environments
- Policies and procedures



## Module 2. Program Security

### Flaws, Faults and Failures

- A **flaw** is a problem with a program
  - **faults**: programmer/specifier/inside view (potential problem, error in code)
  - **failures**: the user/outside view (something actually goes wrong)
  - **faults** **cause** **failures**
- A **security flaw** is a problem that affects security in some way



**How do we find and fix faults?**

- **Test**: intentionally try to cause failures, then work backwards to uncover the underlying fault

- **Patch**: Make small edits to the code
- **Regression testing**: Any time a new patch come in, run whole test suites to ensure no new fault in introduced



**Types of security flaws**

- Some flaws are **intentional/inherent**
  - **Malicious** flaws are intentionally inserted to attack systems
    - Some are for specific systems (**targeted**)
    - Some are for **general** systems
  - **Non-malicious** flaws are often features that are meant to be in the system but can cause a failure when used by an attacker
- Most flaws are caused by **unintentional** program errors, such as overflows...



### Unintentional security flaws

An example: The Heartbleed Bug in OpenSSL SSL/TLS implementation

**Types of unintentional security flaws:**

- Buffer overflows
  - Overflows a buffer on the stack to jump to shell code
  - A single byte can be written past the end of the buffer
  - Overflows of buffers on the heap instead of the stack
  - Jump to other parts of the program, or parts of standard libraries, instead of shellcode
  - Defence
    - Programmer: Use a language with bounds checking
    - Compiler: Place padding between data and return address ("Canaries"), which could detect if the stack has been overwritten
    - Memory: Non-executable stack
    - OS: Stack at random virtual addresses for each process
    - Hardware-assistance: pointer authentication, shadow stack, memory tagging

- Integer overflows
  
  - The conversion between signed and unsigned values could cause integer overflow
- Format string

- Incomplete mediation

  - The ability to ensure that what the user input forms a meaningful structure, e.g. phone number, email address...

  - Attackers may fill in

    - 2340897235982470957: buffer overflow

    - '; DROP DATABASE users; --: SQL injection

      `SELECT ... FROM ... DOB='<input>'`

  - Cross-Site Scripting (XSS) Attacks
  - Defense: Server-side mediation

- TOCTTOU errors

  - Time-Of-Check To Time-Of-Use
  - The state of the system changed between the system verifying an action and executing an action

  - Defense: When performing a privileged action make sure all information to the access control decision is constant

### Malicious code: Malware

Software written with malicious intent, needs to be executed in order to cause harm

**Types of malware**

- Virus: Malicious code that adds itself to benign programs/files, Usually activated by users

  - Attach its own instructions to the end of victim program

    ![1621484157806](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1621484157806.png)

  - In addition to infecting other files, a virus will often try to **infect** the computer itself

  - **Spread**: through emails, internet...

  - **Payload**: At some point, the payload of an infected machine will activate, and do something (usually bad)

- Worms: spreading with no or little user involvement

- Trojans: hidden in seemingly innocent program that you download

- Logic Bombs: hidden in programs already on you machine, triggered under some conditions



**Spotting Virus**

- When should we look for viruses?
  - As files are added to our computer
  - From time to time, scan the entire state of the computer
- How do we look for viruses?
  - Signature-based protection
    - Keep a list of all known viruses. For each virus in the list, store some characteristic feature (the **signature**)
    - To evade signature-based virus scanners, some viruses are **polymorphic** (every time makes a modified copy of itself)
  - Behaviour-based protection
    - Look for suspicious patterns of behaviour, rather than specific code fragments

### Other malicious code

**Web bug**

- A web bug is an object (usually a 1*1 pixel transparent image) embedded in a web page, which is fetched from a different server
- Could get information such as IP address, content of cookies, any personal info the site has about you

**Back Door**

- A back door is a set of instructions designed to bypass the normal authentication mechanism and allow access to the system to anyone who knows the back door exists
- Sources of back doors
  - Froget to remove them
  - Intentionally leave them in testing purposes
  - Intentionally leave them in for maintenance purposes
  - Intentionally leave them in for legal reasons

**Salami attacks**

- A salami attack is an attack that is made up of many smaller, often considered inconsequential, attacks

- Classic example: send the fractions of cents of round-off error from many accounts to a single account owned by the attacker

**Privilege escalation**

- Most systems have the concept of differing levels of privilege for different users
- `telnet -l "-fbin"`

**Rootkits**

- Has two parts
  - First get the priviledge
  - Second hide themselves
    - clean up any log messages
    - modify commands like ls and ps so that they do not report files and processes belonging to the rootkit
    - Modify the kernel so that no user program will ever learn about those files and processes

**Keystroke logging**

- Almost all of the information flow from you to you computer is via the keyboard
- An attacker might install a keyboard logger on your computer to keep a record of: emails/passwords
- Some keyboard loggers are installed by malware
- Application-specific / System keyboard logger / Hardware keyboard logger

**Interface illusions**

- Dragging a scrollbar really install a program to your system

**Phishing**

- An example of an interface illusion
- It looks like you are visiting Paypal's website, but you are really not.
- Hard to detect

**Man-in-the-middle attacks**

- Keyboard logging, interface illusions and phishing are examples of man-in-the-middle attacks
- It intercepts the information and send it to the attacker

### Nonmalicious flaws

**Cover channels**

- An attacker creates a capability to transfer sensitive/unauthorized information through a channel that is not supposed to transmit that information

**Side channels**

- Reflections: There is a reflecting surface close that displays the password typed in
- Cache timing side channels: caches are shared, by timing cache access, a process can learn information about data used by another.

### Controls against Security Flaws

**Security controls - Design**

- **Modularity**: break the problem into a number of small pieces, each responsible for a single subtask
  - Modules should have low *coupling*
- **Encapsulation**: have the modules be mostly self-contained, sharing information only as necessary

- **Information hiding**: The internals of one module should not be visible to other modules

- **Mutual suspicion**: It is a good idea for modules to check that their inputs are sensible before acting on them.

- **Confinement**: If module A needs to depend on module B, it could confine it (like a sandbox)

**Security controls - Implementation**

- **Static code analysis:** there are a number of software products available that will help you find security flaws in your code
- **Hardware assistance**
  - ARM Pointer Authentication
  - Hardware-assisted shadow stack
- **Formal methods**

**Security controls - Change management**

- **Source code and configuration control:** Track all changes to either the source code or the configuration information in some kind.

**Security controls - Code review**

- Empirically, code review is the single most effective way to find faults once the code has been written.
- **Guided walk-through:** the author explains the code to the reviewers
- **Easter egg**: the author inserts intentional flaws for reviewer to find

**Security controls - Testing**

- **Black-box testing:** a test where you just have access to a completed object 

- **Fuzz testing**: supply completely random data to  the object as 
  - input in an API
  - a data file
  - data received from the network
  - UI events

- **White-box testing**: useful for regression testing



## Module3. Operating system security

> OS protects users from each other. Even for a single-user OS, protecting a user from him/herself is a good thing (mistakes, malware)

### Protection in general-purpose operating systems (Memory protection)

**Separation / Isolation**

Keep one user's objects separate from other users
- Physical separation
- Temporal separation
  - Execute different users' programs at different times
- Logical separation
  - User is given the impression that no other users exist

**Memory and address protection**

- Prevent one program from corrupting other programs or data, OS and maybe iteself
- Often the OS can exploit hardware support for this protection
- Memory protection is part of translation from virtual to physical addresses
  - MMU generates exception when the translation goes wrong

**Protection methods**

- **Fence register:** The fence register contains the value of the fence address, which separates the memory into OS part and user part. Exception if memory access below address in fence
- **Base/bounds register pair:** Exception if memory access below/above address in base/bounds register.
- **Tagged architecture:** Each memory word has one or more extra bits that identify access rights to word. 
  - Difficult to port OS from/to other hardware
- **Segmentation**: Each program has multiple address spaces (segments).
  - Virtual addresses consist of two parts: segment name, offset
  - OS maintains the segment translation table, thus could find the memory location
  - Access control can be attached with the segment
  - Advantages
    - Each address reference is checked for protection
    - users can share access to a segment, with potentially different access rights
  - Disadvantages
    - External fragmentation (the available memory is broken up into pieces that are too small)
    - Dynamic length of segment names makes it inefficient to do translation

- **Paging**:

  -  Program virtual address space is divided into equal-sized chunks (pages)

  - Physical memory is divided into equal-sized chunks (frames)
  - Virtual addresses consist of two parts: page number, offset
  - OS keeps mapping from page number to its base physical address in Page Table

  - Advantages
    - Unpopular pages can be moved to disk to free memory
  - Disadvantages
    - Internal fragmentation
    - Assigning different levels of protection to different classes of data

### Access control

> Mandatory reading: 
>
> The morning paper

In general, access control has three goals

- Check every access: Else OS might fail to notice that access ahs been revoked
- Enforce least privilege: Grant program access only to smallest number of objects required to perform a task
- Verify acceptable user: Limit types of activity that can be performed on an object

**Access Control Methods**

- Access control matrix
  - Set of protected objects: $O$ (files or database records)
  - Set of subjects: $S$ (humans, processes)
  - Set of rights: $R$ (read, write, execute, own)
  - Access control matrix consists of entries $a[s,o]$, where $s \in S, o \in O$ and $a[s,o] \in R$ 
  - Access control matrix is typically implemented as 
    - a set of access control lists
    - a set of capabilities (privilege lists)
    - a combination of above

### User authentication

**Two steps**

- **Identification**: Who are you?
- **Authentication**: Prove it!

**Authentication factors**

- Something the user **knows**: Password, PIN, answer to "secret question"
- Something the user **has**: ATM card, badge, browser cookie
- Something the user **is**: Biometrics (fingerprint, face ...)
- Something about the user's **context**: Location, time, devices in proximity

**Different classes** of authentication factors can be combined for more solid authentication: **Two- or multi-factor authentication**

#### Password

**Cryptographic Tools**

- Cryptographic hash: Compute a fixed-length, deterministic output value from a variable-length input value.
- Message Authentication code (MAC): takes another secret key as input
- Symmetric Encryption

The server stores only a digital fingerprint of the password (using a cryptographic has) in the password file

However, offline guessing attack is still possible.

**Defending against guessing attacks**

- UNIX makes guessing attacks harder by specifying a **salt**
- Use an iterated hash function that is expensive to compute and maybe also uses lots of memory

- Use a MAC, instead of a cryptographic hash

**Password Recovery**

- A password cannot normally be recovered from a hash value
- Password reset is more common now

**Interception attacks**

- Attacker intercepts password while it is in transmission from client to server
- One-time passwords make intercepted password useless for later logins
  - Fobs (e.g. RSA SecurID), Authenticator apps
  - Challenge-response protocols

### Security policies and models

Trusting an entity means that if this entity misbehaves, the security of the system fails. We trust an OS if we have confidence that it provides security services.

**Four factors**

- Policy: A set of rules outlining what is secured and why
- Model: A model that implements the policy and that can be used for reasoning about the policy
- Design: A specification of how the OS implements the model
- Trust: Assurance that the OS is implemented according to design

**Trusted software**

- functional correctness
- enforcement of integrity
- Limited privilege: Access rights are minimized and not passed to others
- Appropriate confidence level

**Security policies**

- Military security model

- Each object/subject has a sensitivity/clearance level
- Each object/subject might also be assigned to one or more compartments (Need-to-know rule)
- Subject $s$ can access object $o$ iff $level(s) \geq level(o)$ and $compartments(o) \subseteq compartments(s)$, or saying $s \geq_{dom} o$

**Security models**

In a **lattice**, for every $a$ and $b$, there is a **unique lowest upper bound** $u$ for which $u \geq_{dom} a$ and $u \geq_{dom} b$ and a **unique greatest lower bound** $l$ for which $a \geq_{dom} l$ and $b \geq_{dom} l$

- Bell-La Padula Confidentiality Model (BLP)

  - Users should get information only according to their clearance
  - ss-property (no read up): $s$ should have read access to $o$ only if $C(s) \geq_{dom} C(o)$
  - *-property (no write down): $s$ should have write access to $o$ only if $C(o) \geq_{dom} C(s)$
    - This avoids that a higher level subjects leaks the object to lower level subjects

- Biba Integrity Policy

  - Prevent inappropriate modification of data
  - Dual of BLP
  - subjects and objects are ordered by an integrity classification scheme, $I(s)$ and $I(o)$
- Write access: $s$ can modify $o$ only if $I(s) \geq_{dom} I(o)$
  - Read access: $s$ can read $o$ only if $I(o) \geq_{dom} I(s)$
  - Information flows down
  

### Trusted system design elements

**Several important principles:**

- **Least privilege:** operate using fewest privileges possible
- **Economy of mechanism:** Protection mechanism should be simple and straightforward
- **Open Design:** The adversary knows everything about design
- **Complete mediation**: Every access attempt must be checked
- **Permission based / Fail-safe defaults**: Default should be denial of access
- **Separation of privileges**: Two or more conditions must be met to get access
- **Least common mechanism:** Every shared mechanism could potentially be used as a covert channel

**Access Control**

- Mandatory Access Control
- Discretionary Access Control

**Object reuse protection**: OS should erase returned memory before handing it out to others

**Trusted path:** Only provide sensitive information when only trusted path running

**Accountability and audit:** keep an audit log of all security-related events.

- Provides accountability if something goes bad

**Intrusion detection:** detect exploits



**Security kernel:**

![1623045715685](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1623045715685.png)

**Rings**:

- Some processors support layering based on rings
- x86 architecture supports four rings, but Linux and Windows use only two of them

**Virtualization**:

- virtual memory
- virtual machines



## Module4. Network Security

> Some basic network stuff are omitted here, see CS456 notes

### Threats in networks

#### Interception

- **Packet sniffing:** intercepting and logging all traffic on a wired or wireless link
- `tcpdump`: CLI tool to capture packets on a machine
- `wireshark`: GUI tool to capture packtes
- **Network probe:** in order to learn its topology, services provided and any vulnerabilities
- **Port scanning:** by sending TCP connection requests to a server, we could know which port is open, closed or blocked/filtered (Firewalls)
  - `nmap`: net work mapping tool to probe networks through various protocols including ICMP, TCP

#### Modification and Fabrication

- IP Addresses is lack of integrity

  - The src or dest IP could be modified by malicious parties

  - Ingress and egress filters could prevent IP spoofing 

#### Inerruption

- **Denial-of-service (DoS)** attack venues
  - Exploiting vulnerabilities to result in remote code execution and crashes
  - Resource exhaustion such as Bandwidth and memory

- **ICMP flood:** continuously send ICMP packets
  - Basic ICMP flood mitigation
    - IP address-based blocking: No more that $x$ ICMP packets from IP address Y
    - Rate limiting: no more that $x$ ICMP echo packets per minute

- **Smurf floods:** send ICMP request package from the faked server address to the broadcast function of router, thus every machine respond to the server.

- **SYN flooding:** exhaust server memory allocated for the TCP connections



### TCP Hijacking Attack

![1623841622538](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1623841622538.png)

- **man-in-the-middle attack:** attacker makes server and client talk to the attacker himself, but not to each other



### Network security controls: FireWalls

- Allowlist v.s. denylist: We prefer allowlist

  ![1623842515806](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1623842515806.png)

- Screening router: Packet-filtering rules

  - Examine headers of IP/TCP
    - Ingress: Src IP should be outside network
    - Egress: Src IP should be inside network

- Firewall decisions

  - **Allow** the packet to pass
  - Type-1 deny: **Drop** the packet
  - Type-2 deny: **Reject** the packet but also inform the source

- Defense-in-depth and application proxy architechture

  ![1623842996068](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1623842996068.png)

- Limitations

  - Topological limitations: A network perimeter may not be realistic - un monitored WiFi access points, BYO devices - not all accesses are mediated
  - Trusting insiders: Social engineering, malicious intent

### Intrusion Detection system (IDSes)

IDSes can be used to detect unusual activities that may be initiated by an insider

- Zeek architecture example
  - network -> event engine -> policy script interpreter

- Classification
  - Architecture: collecting raw data
    - host-based IDS (Snort, tripwire)
    - network-based IDS (Zeek)
  - Method: decide if intrusion happens
    - Signature-based: Denylist
    - Specification-based: Manual whitelist
    - Anomaly-based: Empirical whitelist

- Host-based IDS (HIDS)

  ![1623843800624](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1623843800624.png)

- Network-based IDS (NIDS)

  ![1623843824131](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1623843824131.png)

- ![1623844052062](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1623844052062.png)

- **Signature-based IDS**

  - Denylist approach
  - Low false positives (not many false alerts for normal behavior)
  - Fast
  - High false negatives (miss out on new attacks)

- **Specification-based IDS**

  - Allowlist approach
  - Low false negatives (can detect new attacks)
  - Low false positives (not many false alerts for normal behavior)
  - Manually specifying allowlist rules for each application
  - Tripwire example:
    - Generate a policy file: what to monitor, how to monitor it
    - Create a baseline DB: default state of the system
    - Running a check periodically: detect intrusions
    - Updating the baseline DB: user can be habituated to remove monitering for some annoying files.

- **Anomaly-based IDS**

  - Empirical allowlist approach: Infer allowed events via **machine learning**
  - Training period
    - observe a user or network to generate raw data
    - create profiles based on important features of this raw data
  - Testing period: if the user or network deviates significantly from the profile, raise alerts
  - No need to manually create an allowlist
  - Can have some false positives

### Honeypot

- Bait attackers to attack controlled virtual machines, to ultimately deflect them from attacking important hosts
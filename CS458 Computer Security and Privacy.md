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



## Module 5. Internet Application Security and Privacy

### Cryptography

- Cryptography: secret writing, making secret messages
  - turning **plaintext** into **ciphertext**
- Cryptanalysis: Breaking secret messages
- Cryptology is the science that studies both

**Three major types of compnents**

- **Confidentiality** components: preventing Eve from **reading** Alice's messages
- **Integrity** components: preventing Mallory from **modifying** Alice's messages without being detected
- **Authenticity** components: preventing Mallory from **impersonating** (pretending to be) Alice

**Kerckhoffs' Principle**

- The security of a cryptosystem should not rely on a secret that is hard to change

- Strong cryptosystems
  - We assume the attacker (Eve) has when she is trying to break our system
    - Know the algorithm
    - Know some part of the plaintext
    - Know a number of corresponding plaintext/ciphertext pairs
    - Have access to an encryption and/or decryption oracle
  - But still want to prevent Eve!

### Secret-key encryption

- Secret-key encryption is the simplest form of cryptography
- Also called symmetric encryption
- The key Alice uses is the same as the key that Bob uses
- Eve, not knowing the key, should not know the content
- One-time pad: completely unbreakable cryptosystem
  - generate a key $K$ completely randomly
  - the encryption and decryption function is just $XOR$
  - Used in the Washington / Moscow hotline for many years

- In contrast to OTP's perfect security, most cryptosystems have "computational" security
  - This means that it is certain they can be broken, given enough work by Eve

**Stream Ciphers**

- A stream cipher is what you get if you take the OTP, but use a pseudorandom keystream instead of a truly random one
- RC4, ChaCha

**Block ciphers**

- operate on blocks of plaintext (64/128 bits)

- AES

**Modes of operation**

- Cipher Block Chaining (CBC), Counter (CTR), and Galois Counter (GCM) models

Key exchange could be hard in secret-key encryption, thus new techniques are invented.

### Public-key encryption

- Also called asymmetric cryptography
  - Allows Alice to send a secret message to Bog without any prearranged shared secret
  - There is one key for encryption, and a different key for decryption
- RSA, EIGamal, ECC, NTRU

**How does it work?**

- Bob gives everyone a copy of his public encryption key. 
- Alice uses it to encrypt a message, and sends the encrypted message to Bob
- Bob uses his private decryption key to decrypt the message

**Hybrid cryptography**

In addition to having longer keys, public-key cryptography takes a long time to calculate, thus hybrid cryptography is used for almost every application on the Internet today

- Pick a random 128-bit key $K$ for a secret-key cyptosystem
- Encrypt the large message with the key $K$ (e.g. using AES)
- Encrypt the key $K$ using a public-key cryptosystem
- Send the encrypted message and the encrypted key to Bob

### Integrity

Mallory can easily change the message in such a way that the checksum stays the same, thus we need Cryptographic hash functions

- A hash function $h$ takes an arbitrary length string $x$ and computes a fixed length string $y=h(x)$ called a message digest
- MD5, SHA-1, SHA-2, SHA-3
- Three properties
  - Preimage-resistance
  - Second preimage-resistance
  - Collision-resistance

### Authentication

- We have a large class of hash functions, and use a shared secret key to pick the correct one
- These "keyed hash functions" are usually called **Message Authentication Codes**, or **MAC**s

- SHA-1-HMAC, SHA-256-HMAC, CBC-MAC

**Combining ciphers and MACs**

- Encrypt-the-MAC is the recommended strategy
- GCM, CCM or OCB mode

**Repudiation**

- Alice can just claim that Bob made up the message $M$, and calculated the tag $T$ himself
- **Digital signatures**
  - If Bob receives a message with Alice's digital signature on it, then
    - Alice sent the message
    - The message has not been altered since it was sent
    - Bob can prove these facts to a third party (not achieved by MAC)
  - To make a digital signature, Alice sign the message with her private **signature key** (private)
  - To verify Alice's signature, Bob verifies the message with his copy of Alice's **public verification key**

**The Key Management Problem**

- How can Bob find Alice's verification key?
  - Personally (manual keying): SSH does this
  - Friend (web of trust): PGP does this
  - Third party (CAs): TLS / SSL do this

**Certificate authorities**

- A CA is a trusted third party who keeps a directory of people's verification keys

### Link layer security

![1625013925553](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1625013925553.png)

**Don'ts from WEP**

- Randomness: have sufficient randomness
- Integrity: Do not use checksums for integrity. Use keyed MACs instead.
- Go through public reviews cryptographic protocols before standardizing them.

### Network layer security

Prevent other hosts and routers in the middle cannot intercept or modify the packet

- IP Security suite (IPSec): extends IP to provide confidentiality, integrity

- Different Virtual Private Networks (VPNs) architectures are commonly used

- These VPNs use IPSec in one of the two modes

**VPN**: A private network that connects physically distant hosts via virtual links

**Internet Key Exchange(IKE)**: Both source and destination IP addresses agree on a shared symmetric key. Based on this key, we can encrypt and compute MACs over the IP packet or parts of it.

**AH and ESP**: AH provides integrity over original IP header and IPSec payload. ESP provides confidentiality over IPSec payload. ESP trailer provides integrity over IPSec payload.

- Protocol field in the first IP header is set to 50 for AH, 51 for ESP

**IPSec transport mode**

- used in host-to-host VPNs
- Only one plaintext IP header is included in the packet, thus the confidentiality of IP header is not guaranteed

**IPSec tunnel mode**

![1625017404616](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1625017404616.png)

- IPSec is a form of IP-in-IP tunneling

- SSH is another example of tunneling
- Used in *-to-Network VPNs

### Transport layer security

![1625017869698](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1625017869698.png)

![1625018293864](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1625018293864.png)

### Application layer security

- Secure Shell protocol (SSH): provides confidentiality, integrity guarantees to insecure network application

  - SSH protocol parts 

  ![1625018978473](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1625018978473.png)

  - SSH port forwarding

- Securing email
  - Mail transfer: Simple mail transfer protocol (SMTP)
  - Secure email design

### Privacy enhancing technologies - PETs

- Anonymity: Privacy as masks, surveillance. Hiding identities. Tor onion routing.
- Data minimization.: Related to privacy as filters. Minimizing the amount of data collected. Private Information Retrieval.

**Tor**: makes internet browsing unlinkably anonymous



## Module 6. Database security

### Security requirements

#### Authorization / access control

- Types of access control discussed earlier (DAC, MAC, RBAC) also apply to DBs
- Granularity: Access control on relations, records, attributes
- Supporting different query types (operations): SELECT, INSERT, UPDATE, DELETE
- Inference problem: Parts of a database are related, thus could access private information by not directly accessing it

**DAC for databases**

- Your users' privileges can be assigned to other users by the GRANT keyword and revoked from them by the REVOKE keyword
- Type of privileges:
  - Account-level privileges: DBMS functionalities (e.g. shutdown server), creating or modifying tables, routines, users and roles
  - Relation-level privileges: SELECT, UPDATE, REFERENCES privileges in a relation

![1626139724275](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1626139724275.png)

![1626139756811](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1626139756811.png)

- For an SQL query we can generate a view that represents the result

  - Views can be used to only reveal certain columns (attributes after SELECT) and rows (WHERE clause) for access control

  ![1626139959327](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1626139959327.png)

- INSERT & UPDATE query

  ![1626140020375](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1626140020375.png)

- Disadvantages

  - Rely on users to implement the principle of least privilege.
  - System administrator needs to know how privileges are inter-related and assign multiple privileges for a user's task
  - Need to manually change privileges for multiple users who want to perform the same task, or when a user changes positions in an organization. 

**RBAC for databases**

![1626140256632](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1626140256632.png)

Note the role is independent of users

**MAC for databases**

- In the context of databases, multilevel security (MLS) databases provide MAC

- We consider a Bell-La Padula confidentiality model

  - Simple security property - No read ups
  - *-property - No write downs

  ![1626140528128](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1626140528128.png)

  - Creating multiple record with different conf. levels when UPDATEing (polyinstantiation)
  - Select appropriate poly-instantiated record for future read-downs

#### Confidentiality

- Data at rest: On host that runs the database server
  - Hybrid cryptography for file or column-level encryption
  - Full-disk encryption
- Data in transit: TLS secures connection between the client and the server

#### Authentication

DBMS servers are authenticated via certificates presented in the TLS handshake as usual. Root CA can be an organizational entity or third-party. DBMS servers can authenticate remote clients via

- Password-based authentication: client sends username & password over TLS 
- Certificate-based authentication: Client presents a certificate during the third message in the TLS handshake (Client Finished message)
- Authentication via external services (LDAP): Client sends username & password over TLS, server proxies them to a directory server that checks  them and returns an authentication status

#### Integrity

- Authorize a user to modify an elements, but prevent them from making changes that result in an invalid database state
- Ensure correctness of database elements by **element checks**
- Typically enforced by **triggers**: procedures that are automatically executed after INSERT, DELETE, UPDATE...
- **Consistency**: A transaction should take the database from one consistent state to another
- two phase udpate
  - First phase: gather information required for changes, but don't perform any updates, repeat if problem arises
  - Second phase: make changes permanent, repeat if problem arises
  - System log includes instructoin from both phases
    - using the system log, a  DBMS can recover from availability failures, by redoing transactions
    - Unsuccessful transactions can be rolled back

- Referenctial integrity
  - Tables may have a primary key
  - Might also have a single or multiple foreign keys, which are primary keys in some other table
  - There are no dangling foreign keys

#### Availability

- Recovery from system log files
- Redundancy: reduce risk that service is affected from some component failure; transparently transfer operation to anotehr functioning component.
  - Uninterrupted power supplies
  - Multiple hard-drives in RAID configurations
- Database clusters: Redundancy by more machines. Load-balancing among clustered machines.
- Failover: deal with catastrophes etc., when machines are down
  - Clustered machines are in the same physical location
  
  - Setup secondary system: update it regularly, setup DBMS and configure it
  
- Perform periodic backups of the system log, database, configuration files to the secondary system, over a secure channel
  
  - Replay transactions from the log file, to ensure secondary system is in the last state that the primary was at
  
#### Auditability

We want to be able to: 

- retroactively identify who has run these queries without authorization
- hold users accountable and deter such accesses

Setting up auditin

- Set an audit policy (or policies) to observe queries
- DBMS generates an audit trail or log of events that meet the audit policy. This log can be processed later into DB tables
  - Audit policies specify
    - Status: Record when events succeed, fail or both
    - Category: Specifies what events are to be observed. Logging at the right granularity is important.

### Data inference

- Privacy: We want to protect the privacy of the users whose data is in the database
- Utility: We want to allow certain SQL queries, as data analysts want to learn interesting properties of the data
- These two criteria often go against each other.

![1626923918570](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1626923918570.png)

![1626924035555](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1626924035555.png)

### Data release

- Data aggregation: collect different datasets

**Data Mining**

- Tries to automatically find interesting patterns in data using a plethora of techs
- Still need human to judge whether pattern makes sense

Persistent identifiers (Quasi-identifiers) could be used to deanonymize data

Background knowledge relating to the primary data can be used to further deanonymize records

**Prevent anonymity fails**

- Quasi-identifiers
  - Reduce granularity to deter linking: year instead of DOB, only first couple digits of zip code. Increase anonymous set.
  - Remove attributes to prevent linking altogether. We reduce utility of the dataset.
- Publish aggregate statistics
- Change values slightly (add randomness)

#### k-anonymity

1. Pre-processing quasi-identifiers to deter data linking
2. ensure that for each published record, we publish at least  $k-1$ other records with the same quasi-identifier ($k \geq 2$)
3. This constraint ensures that any person who satisfies a given quasi-identifier could correspond to any one of the $k$ records with the same quasi-identifier.

Vulnerable to homogeneity attack: For a given quasi-identifier value, all other data values are identical

Background knowledge attack: For a given quasi-identifier value, other data values are distinct, but you know some background information to rule out many of them.

#### $l$-diversity

For any quasi-identifier value, there should be at least $l$ different values of the sensitive fields. 

#### Perturbing sensitive values

- Perturbations: Change sensitive values slightly by adding randomness
- Linear transform: $y=mx+b$. Easy to reverse to get original $x$
- Adding randomness: $y=x+\phi$, where $\phi$ is picked at random from range $(-\infty, \infty)$, using some probability distribution. Higher noise ($||\phi||) \rightarrow$ lower utility, higher privacy.

- $\phi$ is sampled from a Laplace PDF

![1626926009343](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1626926009343.png)

 **Sensitivity**

![1626933652242](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1626933652242.png)

**Differential privacy guarantee:**

![1626933872637](C:\Users\59129\AppData\Roaming\Typora\typora-user-images\1626933872637.png)


# Knowledge accumulation

> Many a little makes a mickle



## Internet

#### IP Address (IPV4)

- Unique address on the internet, like post address
- Many classes, commonly
  - class C: 192.0.0.0 - 223.255.255.255, with subnet 255.255.255.0
- Inside a LAN, private IP addresses (192.168.1.1) along with NAT are used to prolong the life of IPV4

#### IPV6 Address

- No need for private address, every device could have its own public address
- 

- Many types, commonly
  - global unicast: publicly routable 2000::/3
  - unique local: routable in the LAN FC00::/7 (ipv4 private address)
  - link local: not routable FE80::/10 (ipv4 APIPA)
- Address Configuration
  - To get an IPV4 address, one can use DHCP or Static IP Address (manually set)
  - To get an IPV6 address, Stateless Address Autoconfiguration (SLAAC) is preferred
- [See more Differences](https://www.guru99.com/difference-ipv4-vs-ipv6.html)



#### Ethernet (LAN)

- Physical Layer: Device and cable
  - device: Network interface card (NIC), switch, gateway, bridge
- Data Link Layer: Data transmission protocal



## Linux

#### ifconfig

- Show internet configuration info








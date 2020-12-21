# mDNS-cpp

Zerconf/mDNS message utility code in C++ using IPv4 and IPv6. Self-contained; uses no external libraries.

## Compilation

An example program is provided:

```
g++ -std=c++17 -Wall -Wextra -pedantic main.cpp
```

This example can be run with no arguments to enumerate local interfaces similar to the ``ifconfig`` command. On an early-model iMac, the output looks something like this:

```
$ ./a.out 
lo0 [1]
  AF_PACKET
    ifa_flags: IFF_UP IFF_LOOPBACK IFF_RUNNING IFF_MULTICAST 
    MAC: 00:00:00:00:00:00

  AF_INET
    ifa_flags: IFF_UP IFF_LOOPBACK IFF_RUNNING IFF_MULTICAST 
    ifa_addr: 127.0.0.1
    ifa_netmask: 255.0.0.0
    ifa_broadaddr: 127.0.0.1

  AF_INET6
    ifa_flags: IFF_UP IFF_LOOPBACK IFF_RUNNING IFF_MULTICAST 
    ifa_addr: ::1
    ifa_netmask: ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
    ifa_broadaddr: ::1

  AF_INET6
    ifa_flags: IFF_UP IFF_LOOPBACK IFF_RUNNING IFF_MULTICAST 
    ifa_addr: fe80::1
    ifa_netmask: ffff:ffff:ffff:ffff::
    ifa_broadaddr: (null)

gif0 [2]
  AF_PACKET
    ifa_flags: IFF_POINTOPOINT IFF_MULTICAST 
    MAC: 00:00:00:00:00:00

stf0 [3]
  AF_PACKET
    ifa_flags: 
    MAC: 00:00:00:00:00:00

en0 [4]
  AF_PACKET
    ifa_flags: IFF_UP IFF_BROADCAST IFF_NOTRAILERS IFF_RUNNING IFF_MULTICAST 
    MAC: xx:xx:xx:xx:xx:xx

  AF_INET6
    ifa_flags: IFF_UP IFF_BROADCAST IFF_NOTRAILERS IFF_RUNNING IFF_MULTICAST 
    ifa_addr: fe80::xxxx:xxxx:xxxx:xxxx
    ifa_netmask: ffff:ffff:ffff:ffff::
    ifa_broadaddr: (null)

  AF_INET
    ifa_flags: IFF_UP IFF_BROADCAST IFF_NOTRAILERS IFF_RUNNING IFF_MULTICAST 
    ifa_addr: xxx.xxx.xxx.xxx
    ifa_netmask: 255.255.248.0
    ifa_broadaddr: 10.195.71.255

en1 [5]
  AF_PACKET
    ifa_flags: IFF_UP IFF_BROADCAST IFF_NOTRAILERS IFF_RUNNING IFF_MULTICAST 
    MAC: xx:xx:xx:xx:xx:xx

  AF_INET6
    ifa_flags: IFF_UP IFF_BROADCAST IFF_NOTRAILERS IFF_RUNNING IFF_MULTICAST 
    ifa_addr: fe80::xxxx:xxxx:xxxx:xxxx
    ifa_netmask: ffff:ffff:ffff:ffff::
    ifa_broadaddr: (null)

  AF_INET
    ifa_flags: IFF_UP IFF_BROADCAST IFF_NOTRAILERS IFF_RUNNING IFF_MULTICAST 
    ifa_addr: xxx.xxx.xxx.xxx
    ifa_netmask: 255.255.255.0
    ifa_broadaddr: 192.168.1.255

... etc ...

```

Here, the interface name and index are printed, along with a list of all addressess assigned to that interface. 

Running the example program with the name of a specific interface (or a specific IP address assigned to a local interface) will listen for mDNS messages on that interface/IP.

Interface example (in this case, `en0`; will listen on both IPv4 and IPv6):


```
$ ./a.out en0
'en0' => interface (4)
[family=AF_INET ip=224.0.0.251 port=5353]
[family=AF_INET ip=192.168.68.100 port=0]
[family=AF_INET ip=192.168.68.100 port=0]

***********************
Read 46 bytes
192.168.68.100 => 224.0.0.251 : delivered_on=4
[family=AF_INET ip=192.168.68.100 port=64212]
[family=AF_INET ip=224.0.0.251 port=0]
{id 0 : flags (0) n_question 1 n_answer 0 n_authority 0 n_additional 0}
Questions:
  {name=_services._dns-sd._udp.local., type=PTR (12), class=IN (1)} {TTL=0 rd_len=0}
Answers:
Authority:
Additional:

[family=AF_INET6 ip=xxxx::xx:xxxx:xxx:xxxx port=0]
[family=AF_INET6 ip=ff02::fb port=5353]
[family=AF_INET6 ip=xxxx::xx:xxxx:xxx:xxxx port=0]

***********************
Read 70 bytes
192.168.68.100 => 224.0.0.251 : delivered_on=4
[family=AF_INET ip=192.168.68.100 port=5353]
[family=AF_INET ip=224.0.0.251 port=0]
{id 0 : flags (33792) AAMask QRMask n_question 0 n_answer 1 n_authority 0 n_additional 0}
Questions:
Answers:
  {name=_services._dns-sd._udp.local., type=PTR (12), class=IN (1)} {TTL=4500 rd_len=18} { _OZOmniGraffle7._udp.local. }
Authority:
Additional:


***********************
Read 70 bytes
xxxx::xx:xxxx:xxx:xxxx => ff02::fb : delivered_on=4
[family=AF_INET6 ip=xxxx::xx:xxxx:xxx:xxxx port=5353]
[family=AF_INET6 ip=ff02::fb port=0]
{id 0 : flags (33792) AAMask QRMask n_question 0 n_answer 1 n_authority 0 n_additional 0}
Questions:
Answers:
  {name=_services._dns-sd._udp.local., type=PTR (12), class=IN (1)} {TTL=4500 rd_len=18} { _OZOmniGraffle7._udp.local. }
Authority:
Additional:


***********************
Read 46 bytes
fe80::ba:af36:6e2:4316 => ff02::fb : delivered_on=4
[family=AF_INET6 ip=xxxx::xx:xxxx:xxx:xxxx port=62528]
[family=AF_INET6 ip=ff02::fb port=0]
{id 0 : flags (0) n_question 1 n_answer 0 n_authority 0 n_additional 0}
Questions:
  {name=_services._dns-sd._udp.local., type=PTR (12), class=IN (1)} {TTL=0 rd_len=0}
Answers:
Authority:
Additional:

^CJoined thread4
Joined thread6
done
```

IP example (in this case, the IP6 address `xxxx::xx:xxxx:xxx:xxxx` assigned to `en0` as revealed by running the example with no parameters):


```
$ ./a.out xxxx::xx:xxxx:xxx:xxxx
'xxxx::xx:xxxx:xxx:xxxx' => IPv6 on en0 (4).
[family=AF_INET6 ip=xxxx::xx:xxxx:xxx:xxxx port=0]
[family=AF_INET6 ip=ff02::fb port=5353]
[family=AF_INET6 ip=xxxx::xx:xxxx:xxx:xxxx port=0]
Joined thread4

***********************
Read 46 bytes
xxxx::xx:xxxx:xxx:xxxx => ff02::fb : delivered_on=4
[family=AF_INET6 ip=xxxx::xx:xxxx:xxx:xxxx port=61350]
[family=AF_INET6 ip=ff02::fb port=0]
{id 0 : flags (0) n_question 1 n_answer 0 n_authority 0 n_additional 0}
Questions:
  {name=_services._dns-sd._udp.local., type=PTR (12), class=IN (1)} {TTL=0 rd_len=0}
Answers:
Authority:
Additional:

^CJoined thread6
done
```

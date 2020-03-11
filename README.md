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

### yipfilter

**yipfilter** is a program to create and manage host based IP blacklists and whitelists to control inbound TCP traffic in an easy and scalable way. An application that determines an abusive IP can add the IP to yipfilter blacklist to block inbound traffic from the IP. yipfilter is built on top of [iptables](http://iptables.netfilter.org/) and [ipset](http://ipset.netfilter.org/) that provides a simple interface to control inbound TCP traffic. yipfilter addresses shortcomings associated with the direct usage of iptables such as:

* Managing iptables directly doesn't scale if you have a large dynamic IP blacklists and large number of rules. Instead we use ipset that provides IP hash table.
* iptables doesn't support the notion of auto-rehabilitation of IPs directly. 
* Finally it is simply more powerful and hard to use for someone with a non-networking background.

yipfilter provides two functions:
* IP based dynamic blacklists with auto-expiry 
* IP based access control (whitelist approach)

### Features
* "Store multiple IP addresses and port numbers and match against the collection by iptables at one swoop" ([ipset](http://ipset.netfilter.org/))
* "Dynamically update blacklist sets without perfor-mance penalty" ([ipset](http://ipset.netfilter.org/))
* "Express complex IP address and ports based rule-sets with one single set" ([ipset](http://ipset.netfilter.org/))
* Combines ipset and iptables to form a unified interface
* Ability to set expiry time for an IP
* Superior performance compared to application level (L7) firewalls
* Access control with enhanced security - A non-whitelisted IP cannot establish a TCP and SSL connection with a restrict-ed web application. Protection from OpenSSL heartbleed type attacks.

### Use Cases
* Traffic shaping - yipfilter can greatly reduce the level of network traffic arriving at origin servers due to abuse. 
* Integration with application level (L7) heuristics to detect abusive IPs and block those IPs in network layer at the edge - Protect and save network and system resources for legitimate traffic.
* Whitelist based access control 

### Usage

Prerequisites: **iptables** and **ipset** packages. iptables comes by default on all recent Linux distributions. For ipset, install it using *yum* (Fedora/RHEL) or *apt* (Ubuntu).

For Fedora/RHEL6+:

```
  % yum install -y ipset
```
To start:

```
  % yipfilter.sh --help
```

#### Examples

```
    yipfilter.sh allow -s whitelist -p 443 -t ip -f whitelist.txt
    
    yipfilter.sh deny -s blacklist -p 443 -t ip -f blacklist.txt

    yipfilter.sh destroy -s blacklist

    yipfilter.sh list -s blacklist

    yipfilter.sh list

    yipfilter.sh add -s blacklist -e 600 -E 72.134.234.56

    yipfilter.sh test -s blacklist -E 72.134.234.56

    echo "72.134.234.56" | yipfilter.sh add -s blacklist -e 600

    yipfilter.sh save -s blacklist > blacklist.yipf

    yipfilter.sh restore -s blacklist -f blacklist.yipf
```

#### Documentation

[Man Page](https://github.com/prbinu/yipfilter/blob/master/docs/yipfilter.md)

## License

This software is free to use under the Yahoo! Inc. BSD license.
See the [LICENSE file][] for license text and copyright information.

[LICENSE file]: https://github.com/prbinu/yipfilter/blob/master/LICENSE.md

License:

This software is free to use under the Yahoo! Inc. BSD license. See the LICENSE file for license text and copyright information.

TODO:
  IPv6 support


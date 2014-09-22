<HTML><HEAD><TITLE>Manpage of YIPFILTER</TITLE>
</HEAD><BODY>

# YIPFILTER

Section: User Commands (1)
Updated: July 2014
[Index](#index)
[Return to Main Contents](http://localhost/cgi-bin/man/man2html)

* * *

<A NAME="lbAB">&nbsp;</A>

## NAME

yipfilter - A powerfull, easy to use host firewall for IP blacklisting (and whitelisting too!)
<A NAME="lbAC">&nbsp;</A>

## SYNOPSIS

**yipfilter** _COMMAND -s SET _[_-hvd_] [_-p PORT_] [_-t TYPE_] [_-f FILE_] [_-e TIMEOUT_] [_-E ELEMENT_] [_-m MAXELEM_]
<A NAME="lbAD">&nbsp;</A>

## DESCRIPTION

yipfilter is program to create and manage host based IP blacklists and whitelists to control inbound TCP traffic. An application that determines an abusive IP can add the IP to yipfilter blacklist to block inbound traffic from the IP. yipfilter is built on top of iptables and ipset that provides a simple interface to control inbound TCP traffic.
<A NAME="lbAE">&nbsp;</A>

### COMMANDS

<DL COMPACT>
<DT>allow -s SET<DD>
Creates a whitelist set
<DT>deny -s SET<DD>
Creates a blacklist set
<DT>destroy -s SET<DD>
Delete/Remove a set
<DT>list [-s SET]<DD>
List the entries of a named set or all sets
<DT>add -s SET<DD>
Add one or more ip/netblocks to an existing set
<DT>del -s SET<DD>
Delete entry from the named set
<DT>test -s SET -E ELEM<DD>
Test entry in the named set
<DT>reset<DD>
Remove/destroy all filter sets from the system
<DT>save -s SET<DD>
Save current settings to stdout
<DT>restore<DD>
Restore a saved state from the given state file (-f)
Use restore for batch addition of ips
</DL>
<A NAME="lbAF">&nbsp;</A>

### OPTIONS

<DL COMPACT>
<DT>-s SET<DD>
The name of the filter set
<DT>-p PORT[,PORT,..]<DD>
The destination TCP port number for allow/deny. Default
port is 443. You also can specify multiple ports
seperated by ',' eg. 443, 80, 4080
<DT>-t TYPE<DD>
{net | ip} Address family. IPv4 netblock (CIDR) address
or a host IPv4 address. Default is 'ip'.
<DT>-f FILE<DD>
Input file with the list of IPv4 ips or ip net blocks.
With no FILE or when FILE is -, read standard input.
No IPv6 support in this release
<DT>-w http[s]<DD>
HTTP[S] location. (not supported yet)
<DT>-e TIMEOUT<DD>
Expiry timeout in seconds. Eg. block ips 'n' seconds
<DT>-E ELEMENT<DD>
One ip or a netblock, primarly used with 'test' command
-E and -f options are mutually exclusive
<DT>-m MAXELEM<DD>
The maximal number of elements which can be stored in
the set, default 65536.
<DT>-v<DD>
Verbose mode. Can be used multiple times for increased
verbosity
<DT>-d<DD>
Dryrun - Check to see the input IPs/netblocks are valid
(not supported yet)
<DT>-h<DD>
Display this help and exit
</DL>
<A NAME="lbAG">&nbsp;</A>

### EXAMPLES

<DL COMPACT>
<DT><DD>
yipfilter allow -s whitelist -p 443 -t ip -f whitelist.txt
<DT><DD>
yipfilter deny -s blacklist -p 443 -t ip -f blacklist.txt
<DT><DD>
yipfilter destroy -s blacklist
<DT><DD>
yipfilter list -s blacklist
<DT><DD>
yipfilter list
<DT><DD>
yipfilter add -s blacklist -e 600 -E 72.134.234.56
<DT><DD>
yipfilter test -s blacklist -E 72.134.234.56
<DT><DD>
echo &quot;72.134.234.56&quot; | yipfilter add -s blacklist -e 600
<DT><DD>
yipfilter save -s blacklist &gt; blacklist.yipf
<DT><DD>
yipfilter restore -s blacklist -f blacklist.yipf
</DL>
<A NAME="lbAH">&nbsp;</A>

## REPORTING BUGS

Report bugs to &lt;[yipfilter@yahoo.com](mailto:yipfilter@yahoo.com)&gt;.
<A NAME="lbAI">&nbsp;</A>

## COPYRIGHT

Copyright (C) 2014 Yahoo Inc.
<P>
Written by Binu P. Ramakrishnan
<A NAME="lbAJ">&nbsp;</A>

## SEE ALSO

[iptables](http://ipset.netfilter.org/iptables.man.html)(8) [ipset](http://ipset.netfilter.org/ipset.man.html)(8)
<P>

* * *

This document was created by
[man2html](http://localhost/cgi-bin/man/man2html),
using the manual pages.

Time: 23:51:14 GMT, September 21, 2014
</BODY>
</HTML>


#! /bin/bash
# help2man - http://www.gnu.org/software/help2man
# This tool used to produce simple manual pages from the ‘--help’ and ‘--version’ output of other commands
ln -s ../yipfilter.sh yipfilter
help2man --include=./yipfilter.h2m --name='A powerfull, easy to use host firewall for IP blacklisting (and whitelisting too!)' ./yipfilter > yipfilter.1
# create html file
cat yipfilter.1 | groff -mandoc -Thtml > yipfilter.html
rm yipfilter

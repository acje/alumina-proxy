#!/bin/sh
echo "$$" > "/w/pid/${STAMP}.candidate.pid"
exec /usr/local/sbin/haproxy -db -f /cfg/haproxy.cfg

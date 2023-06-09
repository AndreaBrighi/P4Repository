# Asymmetric flow without window

## Introduction
![topology](./topo.png)

Basic idea is that to calculate the threshold of the incoming traffic and the outgoing traffic of a specific flow. 

A register called last_seen group every flow that passed the switch with the correspondent threshold.

When a packet arrives the threshold is upgraded.

If the threshold is reached an action must be performed, in this case a simple drop().

make run

xterm h1 h2

./mytunnel_receive.py

./mytunnel_send.py 10.0.1.1 "P4 is cool" -
-dst_id 1

got a packet
###[ Ethernet ]###
  dst       = ff:ff:ff:ff:ff:ff
  src       = 00:00:00:00:01:01
  type      = 0x1212
###[ MyTunnel ]###
     pid       = 2048L
     dst_id    = 2L
     IP_MAL    = 0.0.0.0
     TIME      = 0L
     FLAG      = 0L
###[ IP ]###
        version   = 4L
        ihl       = 5L
        tos       = 0x0
        len       = 30
        id        = 1
        flags     = 
        frag      = 0L
        ttl       = 64
        proto     = hopopt
        chksum    = 0x63dd
        src       = 10.0.1.1
        dst       = 10.0.2.2
        \options   \
###[ Raw ]###
           load      = 'P4 is cool'

iperf -s

iperf -c 10.0.1.1

./mytunnel_receive.py

./mytunnel_send.py 10.0.1.1 "P4 is cool" -
-dst_id 1

got a packet
###[ Ethernet ]###
  dst       = ff:ff:ff:ff:ff:ff
  src       = 00:00:00:00:02:02
  type      = 0x1212
###[ MyTunnel ]###
     pid       = 2048L
     dst_id    = 1L
     IP_MAL    = 10.0.1.1
     TIME      = 0L
     FLAG      = 1L
###[ IP ]###
        version   = 4L
        ihl       = 5L
        tos       = 0x0
        len       = 30
        id        = 1
        flags     = 
        frag      = 0L
        ttl       = 64
        proto     = hopopt
        chksum    = 0x63dd
        src       = 10.0.2.2
        dst       = 10.0.1.1
        \options   \
###[ Raw ]###
           load      = 'P4 is cool'


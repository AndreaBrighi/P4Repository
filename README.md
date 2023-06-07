# Asymmetric flow without window

## Introduction
![topology](./topo.png)

Basic idea is that to calculate the threshold of the incoming traffic and the outgoing traffic of a specific flow. 

A register called last_seen group every flow that passed the switch with the correspondent threshold.

When a packet arrives the threshold is upgraded.

If the threshold is reached an action must be performed, in this case a simple drop().




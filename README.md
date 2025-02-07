# Snipher

Snipher is a network packet sniffer created from scratch in C using raw sockets.

## How does it work

Snipher uses sockers of family ```AF_PACKET``` and type ```SOCK_RAW``` to receive network packets directly from NIC before the IP layer, transport layer and datalink layer (ethernet) headers are fully stripped.
As a result we are able to inspect all header properties and the raw data.

Snipher as of now only allows capturing TCP or UDP packers under IP protocol.

## Build

```
gcc -o snipher snipher.c
```

## Usage

You can use mulitple options for filtering while capturing packets with Snipher :

- **--tcp** : Capture only TCP packets
- **--udp** : Capture only UDP packets
- **--sip** : Filter packets by given source IP
- **--dip** : Filter packets by given destination IP
- **--sif** : Filter packets by source interface set as given interface. Matches source MAC of the packet against provided interface's MAC adress. Useful for filtering packets leaving from a given interface.
- **--dif** : Filter packets by destination interface set as given interface. Matches destination MAC of the packet against provided interface's MAC adress. Useful for filtering packets arriving at a given interface on the machine.
- **--sport** : Filter packets by source port
- **--dport** : Filter packets by destination port
- **--logfile** : Name of th log file for capturing packet data. Defaults to snipher_log.tx.

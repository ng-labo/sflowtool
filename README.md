## The functions on this branch
### lookup agent,ifalias

look up agent and ifalias into readable printing text.

```
sflowtool -K agent_ifalias.txt -L agent,inputPort,srcIP,dstIP,IPProtocol
```

agent_ifalias.txt shall be arranged by agent-id, if-index, agent-name, ifalias in camma separating.

```
2130706433 1 localhost lo
2130706433 2 localhost ens3
2130706433 1073741823 localhost ens3
```

### matching ipaddress or ipprotocol filter for output

- ipaddress  : ipv4 and ipv6, able to add prefix length
               examine srcIP,srcIP6,dstIP,dstIP6 and print if match any
- ipprotocol : number, be able to use some alias(tcp, udp, icmp, icmp58)

```
sflowtool -T 8.8.8.8,udp -L srcIP,dstIP,IPProtocol
sflowtool -T 2001::/16,icmp58 -L srcIP,dstIP,IPProtocol
```

now -T option can be set multi-times.

### matching payload filter for output

text base matching for payload decoded into ascii.
unreadable characters will translate into '.' all.

```
sflowtool -R currentTime -T udp -L agent,inputPort,srcIP,dstIP,IPProtocol,payload
```

### forward to the redis-server

requires [libhiredis](https://github.com/redis/hiredis)

This option is effective just -L option, which outputs line is ordered by user.
To run, be assigned to option '-M', without argument, redis-server must be in localhost:

It uses the name of queue 'sflow'.
This process does not watch the queue status on the redis-server. Just to send messages.

```
$ # let sflowtool run
$ ./sflowtool -M -L srcIP,dstIP,sampledPacketSize

$ # show the status of queue by redis-client
$ redis-cli
127.0.0.1:6379> LRANGE sflow 0 -1
 1) "192.168.102.221,192.168.124.194,70,1518"
 2) "192.168.124.165,192.168.4.152,1468,70"
 3) "192.168.124.247,192.168.64.197,78,1518"
 4) "192.168.66.52,192.168.124.194,58,100"
127.0.0.1:6379>
```

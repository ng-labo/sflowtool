### build-in bz2 reader

You can execute the command with bz2 archived pcap.
Following commanlines will bring same result.
```
bzip2 -dc log.pcap.bz2 | sflowtool -r - -l
sflowtool -r log.pcap -l
sflowtool -r log.pcap.bz2 -l
cat log.pcap | sflowtool -r - -l
```


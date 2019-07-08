# SNI-Sniffer

Extract domains visited through SNI sniffing.

```
Started capturing on ens33
TCP V4(192.168.14.128):50596 -> V4(172.217.27.46):443
SNI: [
    "google.com",
]
TCP V4(192.168.14.128):51262 -> V4(117.18.232.200):443
SNI: [
    "az764295.vo.msecnd.net",
]
TCP V4(192.168.14.128):45508 -> V4(111.221.29.254):443
SNI: [
    "vortex.data.microsoft.com",
]
TCP V4(192.168.14.128):40952 -> V4(172.217.160.10):443
SNI: [
    "safebrowsing.googleapis.com",
]
TCP V4(192.168.14.128):37934 -> V4(35.166.72.120):443
SNI: [
    "shavar.services.mozilla.com",
]
```

## Notes
For interface sniffing you must run the program as root.

## TO-DO
- [ ] Show Date/Time Request was made
- [ ] Output to csv/json
- [ ] Better formatted output

```
Date/Time Request was made,
Source Address,
Source Port,
SNI,
Remote Address,
Remote Port,
```

## Sources

This project is built based on the following sources.

- https://github.com/rusticata/rusticata/blob/master/src/tls.rs
- https://github.com/rusticata/pcap-parse/blob/master/src/main.rs
- https://github.com/libpnet/libpnet/blob/master/examples/packetdump.rs
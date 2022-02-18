# OpenBMP Whois Daemon

A whois daemon that exposes common queries, such as looking glass, asn lookups, etc. in textual format. 
This daemon runs queries similar to the grafana dashboards. 

## Build

```
go mod tidy
go build -o obmp-whoisd
```


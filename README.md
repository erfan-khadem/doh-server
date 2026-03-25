# doh-server
A Custom DoH Server Implementation with Load Balancing Capabilities

# Building

```bash
go build -v -trimpath -ldflags "-s -w -buildid="
```

# Testing

First, fill `config.json` with appropriate values and configurations. Then
build run the server as:

```bash
./doh-server config.json
```

At last, deploy the server behind `nginx` or your reverse proxy of choice for
https termination (or run with your own https certificate in standalone mode)
and test using `dig`:

```bash
dig example.com A @doh.example.com +https
dig example.com HTTPS @doh.example.com +https
dig example.com HTTPS @doh.example.com +https +https-get
```

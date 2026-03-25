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

# dns-forwarder

This program can be used to multiplex dns traffic between multiple upstream DNS resolvers.

After building, run the forwarder like so (with an upstream resolver of your choice, `doh`, `tcp`, and `udp` are supported):

```bash
./dns-forwarder -target "udp://8.8.8.8:53" -listen "127.0.0.1:4197" -pool 5
```

Then, to use the `dns-forwarder` with `doh-server`, you can set `"upstream_dns"` to `127.0.0.1:4197` in `config.json`.

# Splicore

Splicore is an independent multi-protocol proxy core written in Go for server and client deployments.

## Features

- Server and client runtimes
- Multi-protocol architecture
- Native TUN runtime
- Routing, DNS, and policy engine
- API and CLI management
- Single-binary deployment

## Build

Requires Go 1.26.3 or newer.

```sh
CGO_ENABLED=0 go build -trimpath -tags with_quic,with_utls,with_gvisor -o splicore ./cmd/splicore
```

## Usage

```sh
./splicore
./splicore version
```

Linux binaries are available from [Releases](https://github.com/ike-sh/Splicore/releases).

## License

See [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md).

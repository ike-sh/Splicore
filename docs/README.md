# Splicore documentation

## Users and operators

- [Installation and source builds](INSTALLATION.md)
- [Bootstrap configuration and persistent state](CONFIGURATION.md)
- [CLI and resource transactions](CLI.md)
- [Linux operations and platform limits](OPERATIONS.md)
- [Upgrades and backups](UPGRADE.md)
- [Uninstallation](UNINSTALL.md)
- [Redacted support bundles](SUPPORT_BUNDLE.md)
- [Native distribution contract](DISTRIBUTION.md)

## Protocols and configuration

- [VLESS, Vision, TLS and REALITY combinations](protocol/VLESS.md)
- [TCP FinalMask: header-custom, fragment and Sudoku](architecture/FINALMASK.md)
- [AnyTLS: TLS, v2/v1, multiplexing, padding and UoT2](architecture/ANYTLS.md)
- [AnyTLS server configuration](configuration/inbound/anytls.md)
- [AnyTLS client configuration](configuration/outbound/anytls.md)
- [Shared stream transports](architecture/SHARED_TRANSPORT.md)
- [XHTTP H1/H2 transport](architecture/XHTTP.md) / [中文](architecture/XHTTP.zh.md)
- [Modern mKCP transport](architecture/MKCP.md)
- [Native NaiveProxy H2/H3 CONNECT](architecture/NAIVE.md)
- [Specialized Hysteria transport for Hysteria2](architecture/HYSTERIA_TRANSPORT.md)

## Integrators

- [Core architecture](ARCHITECTURE.md)
- [Core scope](architecture/CORE_SCOPE.md)
- [Protocol and feature capabilities](architecture/CAPABILITY_MATRIX.md)
- [Local control API](api/README.md)
- [Licenses and attribution](architecture/LICENSE_BOUNDARIES.md)

Splicore bootstrap and resource documents use the Core's own schema. External
client formats are export projections. Platform support is experimental;
Linux arm64 is BUILD ONLY. See operations for host networking limits.

module github.com/ike-sh/Splicore

go 1.26.3

require (
	github.com/gofrs/uuid/v5 v5.5.1
	github.com/google/nftables v0.3.0
	github.com/gorilla/websocket v1.5.3
	github.com/metacubex/utls v1.8.7
	github.com/miekg/dns v1.1.72
	golang.org/x/crypto v0.54.0
	golang.org/x/sys v0.47.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
	gvisor.dev/gvisor v0.0.0-20261004063249-f57b8fc79db4
	modernc.org/sqlite v1.59.0
)

require (
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/metacubex/cpu v0.1.0 // indirect
	github.com/metacubex/hkdf v0.1.0 // indirect
	github.com/metacubex/hpke v0.1.0 // indirect
	github.com/metacubex/mlkem v0.1.0 // indirect
	github.com/metacubex/randv2 v0.2.0 // indirect
)

require (
	github.com/refraction-networking/utls v1.8.2 // indirect
	github.com/vishvananda/netns v0.0.5
	golang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f // indirect
	golang.org/x/mod v0.38.0 // indirect
	golang.org/x/net v0.57.0
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/grpc v1.80.0
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/apernet/quic-go v0.63.1-0.20261004180939-a10df75c260c
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/enfein/mieru/v3 v3.38.0
	github.com/google/btree v1.1.3 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.19.1 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/metacubex/jls-quic-go v0.0.0-20260727080412-732f2fc9a34d
	github.com/metacubex/jls-tls v0.0.0-20260723084315-67adc0e2f796
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.63.0
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.48.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
	golang.zx2c4.com/wireguard v0.0.0-20261024220952-b3bc704ef0ee
	golang.zx2c4.com/wireguard/windows v0.5.3
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260401024825-9d38bb4040a9 // indirect
	lukechampine.com/blake3 v1.3.0
	modernc.org/libc v1.75.7 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

require (
	github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828
	github.com/mdlayher/genetlink v1.3.2
	github.com/mdlayher/netlink v1.7.3-0.20250113171957-fbb4dce95f42
)

replace github.com/amnezia-vpn/amneziawg-go/v3 => ./third_party/amneziawg-go

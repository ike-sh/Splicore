// wireguard-peer is a test-only process using the pinned, unmodified official
// WireGuard device and netstack APIs. It imports no Splicore runtime packages.
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const revision = "b3bc704ef0ee21a36298601a9e1e5ff90377ac52"

type request struct {
	Op        string   `json:"op"`
	PeerKey   string   `json:"peer_key"`
	Addresses []string `json:"addresses"`
	Allowed   []string `json:"allowed_ips"`
	PSK       string   `json:"psk"`
	Keepalive int      `json:"keepalive"`
	Endpoint  string   `json:"endpoint"`
	Network   string   `json:"network"`
	Target    string   `json:"target"`
	Payload   []byte   `json:"payload"`
	TimeoutMS int      `json:"timeout_ms"`
}

func keyHex(key string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("invalid peer key")
	}
	return hex.EncodeToString(b), nil
}

type peer struct {
	device  *device.Device
	stack   *netstack.Net
	key     string
	closers []io.Closer
}

func (p *peer) close() {
	for _, c := range p.closers {
		_ = c.Close()
	}
	if p.device != nil {
		p.device.Close()
	}
}

func (p *peer) init(r request) (any, error) {
	private, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	p.key, err = keyHex(r.PeerKey)
	if err != nil {
		return nil, err
	}
	var addresses []netip.Addr
	for _, value := range r.Addresses {
		a, err := netip.ParseAddr(value)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, a)
	}
	tun, stack, err := netstack.CreateNetTUN(addresses, nil, 1420)
	if err != nil {
		return nil, err
	}
	p.stack = stack
	logger := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "official-peer: "+format+"\n", args...)
		},
	}
	p.device = device.NewDevice(tun, conn.NewDefaultBind(), logger)
	config := "private_key=" + hex.EncodeToString(private[:]) + "\nlisten_port=0\npublic_key=" + p.key + "\n"
	if r.PSK != "" {
		psk, err := keyHex(r.PSK)
		if err != nil {
			return nil, err
		}
		config += "preshared_key=" + psk + "\n"
	}
	for _, prefix := range r.Allowed {
		if _, err := netip.ParsePrefix(prefix); err != nil {
			return nil, err
		}
		config += "allowed_ip=" + prefix + "\n"
	}
	config += "persistent_keepalive_interval=" + strconv.Itoa(r.Keepalive) + "\n"
	if err := p.device.IpcSet(config); err != nil {
		return nil, err
	}
	if err := p.device.Up(); err != nil {
		return nil, err
	}
	for _, ip := range addresses {
		listener, err := stack.ListenTCPAddrPort(netip.AddrPortFrom(ip, 30034))
		if err != nil {
			return nil, err
		}
		p.closers = append(p.closers, listener)
		go func() {
			for {
				c, err := listener.Accept()
				if err != nil {
					return
				}
				go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
			}
		}()
		packet, err := stack.ListenUDPAddrPort(netip.AddrPortFrom(ip, 30035))
		if err != nil {
			return nil, err
		}
		p.closers = append(p.closers, packet)
		go func() {
			buffer := make([]byte, 65535)
			for {
				n, address, err := packet.ReadFrom(buffer)
				if err != nil {
					return
				}
				_, _ = packet.WriteTo(buffer[:n], address)
			}
		}()
	}
	current, err := p.device.IpcGet()
	if err != nil {
		return nil, err
	}
	port := 0
	for _, line := range strings.Split(current, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			port, _ = strconv.Atoi(strings.TrimPrefix(line, "listen_port="))
		}
	}
	if port == 0 {
		return nil, fmt.Errorf("official peer has no UDP listener")
	}
	return map[string]any{"public_key": private.PublicKey().String(), "listen_port": port, "revision": revision}, nil
}

func (p *peer) dial(r request) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(r.TimeoutMS)*time.Millisecond)
	defer cancel()
	c, err := p.stack.DialContext(ctx, r.Network, r.Target)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	deadline, _ := ctx.Deadline()
	_ = c.SetDeadline(deadline)
	if _, err = c.Write(r.Payload); err != nil {
		return nil, err
	}
	want := make([]byte, len(r.Payload))
	if r.Network == "udp" {
		n, err := c.Read(want)
		return map[string]any{"payload": want[:n]}, err
	}
	_, err = io.ReadFull(c, want)
	return map[string]any{"payload": want}, err
}

func run() error {
	p := &peer{}
	defer p.close()
	decoder := json.NewDecoder(bufio.NewReader(os.Stdin))
	encoder := json.NewEncoder(os.Stdout)
	for {
		var r request
		if err := decoder.Decode(&r); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		var response any
		var err error
		switch r.Op {
		case "init":
			if p.device != nil {
				err = fmt.Errorf("already initialized")
			} else {
				response, err = p.init(r)
			}
		case "endpoint":
			if _, _, err = net.SplitHostPort(r.Endpoint); err == nil {
				err = p.device.IpcSet("public_key=" + p.key + "\nendpoint=" + r.Endpoint + "\n")
			}
			response = map[string]bool{"ok": err == nil}
		case "dial":
			response, err = p.dial(r)
		case "close":
			return nil
		default:
			err = fmt.Errorf("unknown peer operation")
		}
		if err != nil {
			response = map[string]string{"error": err.Error()}
		}
		if err := encoder.Encode(response); err != nil {
			return err
		}
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

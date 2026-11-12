package netbench

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestMeasuredRealTCPDirectionsAndUDPIntegrity(t *testing.T) {
	tcp, udp := Targets(t, "127.0.0.1", 10e9)
	path := filepath.Join(t.TempDir(), "raw.jsonl")
	r, err := NewRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	s := Scenario{Name: "real-sockets", Protocol: "direct", Ingress: "127.0.0.1", Egress: "127.0.0.1", Network: "mixed", Connections: 1, Bytes: 65536, PacketBytes: 1200, PacketsPerSecond: 1000, Probes: 3, TimeoutSeconds: 10}
	for _, mode := range []string{"upload", "download", "duplex"} {
		s.Mode = mode
		if err := RunTCP(context.Background(), r, s, 0, func(context.Context) (net.Conn, error) { return net.Dial("tcp", tcp.String()) }); err != nil {
			t.Fatal(mode, err)
		}
	}
	if err := RunUDP(context.Background(), r, s, 0, func(context.Context) (net.PacketConn, error) { return net.ListenPacket("udp", "127.0.0.1:0") }, udp); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	connections := 0
	for decoder.More() {
		var row map[string]any
		if err := decoder.Decode(&row); err != nil {
			t.Fatal(err)
		}
		if row["kind"] == "connection" {
			connections++
			if row["status"] != "BASELINE" {
				t.Fatal(row)
			}
			if row["network"] == "udp" && row["sent_packets"] != row["received_packets"] {
				t.Fatal("unaccounted loopback UDP loss", row)
			}
		}
	}
	if connections != 4 {
		t.Fatalf("missing raw results: %d", connections)
	}
}

func TestMeasurementRejectsUnacknowledgedTCP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := l.Accept()
		if e == nil {
			c.Write([]byte{0xff})
			c.Close()
		}
	}()
	r, err := NewRecorder(filepath.Join(t.TempDir(), "raw.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	s := Scenario{Name: "invalid-reply", Mode: "duplex", Bytes: 65536, Probes: 1, TimeoutSeconds: 3}
	err = RunTCP(context.Background(), r, s, 0, func(context.Context) (net.Conn, error) { return net.Dial("tcp", l.Addr().String()) })
	<-done
	if err == nil {
		t.Fatal("a corrupt readiness reply was accepted as throughput evidence")
	}
}

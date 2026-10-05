//go:build darwin || linux || windows

package oomprofile

import (
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime/pprof"
	"slices"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestWriteFileProfiles(t *testing.T) {
	profiles := map[string][]string{
		"allocs":       {"alloc_objects", "alloc_space", "inuse_objects", "inuse_space"},
		"heap":         {"alloc_objects", "alloc_space", "inuse_objects", "inuse_space"},
		"block":        {"contentions", "delay"},
		"mutex":        {"contentions", "delay"},
		"goroutine":    {"goroutine"},
		"threadcreate": {"threadcreate"},
	}
	for name, sampleTypes := range profiles {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name+".pb")
			if err := WriteFile(path, name); err != nil {
				t.Fatal(err)
			}
			types, _ := readProfile(t, path)
			if !slices.Equal(types, sampleTypes) {
				t.Fatalf("sample types = %v, want %v", types, sampleTypes)
			}
		})
	}
}

func TestWriteFileGoroutineLabels(t *testing.T) {
	path := filepath.Join(t.TempDir(), "goroutine.pb")
	pprof.Do(context.Background(), pprof.Labels("qf003", "public-api"), func(context.Context) {
		if err := WriteFile(path, "goroutine"); err != nil {
			t.Fatal(err)
		}
	})
	_, strings := readProfile(t, path)
	for _, want := range []string{"qf003", "public-api"} {
		if !slices.Contains(strings, want) {
			t.Fatalf("goroutine profile lost label %q", want)
		}
	}
}

func TestWriteFileRejectsUnsupportedWithoutTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing")
	for _, name := range []string{"", "cpu", "unknown"} {
		if err := os.WriteFile(path, []byte("preserved"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := WriteFile(path, name); err == nil {
			t.Fatalf("accepted unsupported profile %q", name)
		}
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "preserved" {
			t.Fatalf("unsupported profile changed destination: %q, %v", data, err)
		}
	}
}

func TestWriteFileCreateError(t *testing.T) {
	// A directory cannot be truncated as a profile on any supported platform.
	directory := t.TempDir()
	if err := WriteFile(directory, "heap"); err == nil {
		t.Fatal("missing destination error")
	}
	if info, err := os.Stat(directory); err != nil || !info.IsDir() {
		t.Fatalf("destination directory changed: %v, %v", info, err)
	}
}

// Read the documented gzip/protobuf format and resolve SampleType references
// through its StringTable. This validates profile metadata and labels without
// depending on runtime-private data layouts.
func readProfile(t *testing.T, path string) ([]string, []string) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	var types []uint64
	var strings []string
	for len(data) > 0 {
		number, wire, n := protowire.ConsumeTag(data)
		if n < 0 {
			t.Fatal(protowire.ParseError(n))
		}
		data = data[n:]
		length := protowire.ConsumeFieldValue(number, wire, data)
		if length < 0 {
			t.Fatal(protowire.ParseError(length))
		}
		if number == 1 || number == 6 {
			if wire != protowire.BytesType {
				t.Fatalf("invalid profile field %d", number)
			}
			value, n := protowire.ConsumeBytes(data)
			if n < 0 {
				t.Fatal(protowire.ParseError(n))
			}
			if number == 6 {
				strings = append(strings, string(value))
			} else {
				for len(value) > 0 {
					field, kind, n := protowire.ConsumeTag(value)
					if n < 0 {
						t.Fatal(protowire.ParseError(n))
					}
					value = value[n:]
					length := protowire.ConsumeFieldValue(field, kind, value)
					if length < 0 {
						t.Fatal(protowire.ParseError(length))
					}
					if field == 1 {
						if kind != protowire.VarintType {
							t.Fatal("invalid sample type")
						}
						index, _ := protowire.ConsumeVarint(value)
						types = append(types, index)
					}
					value = value[length:]
				}
			}
		}
		data = data[length:]
	}
	if len(strings) == 0 || strings[0] != "" || len(types) == 0 {
		t.Fatal("incomplete pprof profile")
	}
	result := make([]string, len(types))
	for i, index := range types {
		if index >= uint64(len(strings)) {
			t.Fatal("sample type references missing string")
		}
		result[i] = strings[index]
	}
	return result, strings
}

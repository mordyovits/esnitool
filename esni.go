package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

var known_version = [2]byte{0xFF, 0x01}

var suites = map[[2]byte]string{
	[2]byte{0x13, 0x01}: "TLS_AES_128_GCM_SHA256",
	[2]byte{0x13, 0x02}: "TLS_AES_256_GCM_SHA384",
	[2]byte{0x13, 0x03}: "TLS_CHACHA20_POLY1305_SHA256",
	[2]byte{0x13, 0x04}: "TLS_AES_128_CCM_SHA256",
	[2]byte{0x13, 0x05}: "TLS_AES_128_CCM_8_SHA256",
}

func suiteToName(cs [2]byte) string {
	s, ok := suites[cs]
	if !ok {
		return fmt.Sprintf("unknown (% X)", cs)
	}
	return s
}

var named_groups = map[[2]byte]string{
	// Elliptic Curve Groups (ECDHE)
	[2]byte{0x00, 0x17}: "ecp256r1",
	[2]byte{0x00, 0x18}: "secp384r1",
	[2]byte{0x00, 0x19}: "secp521r1",
	[2]byte{0x00, 0x1D}: "x25519",
	[2]byte{0x00, 0x1E}: "x448",

	// Finite Field Groups (DHE)
	[2]byte{0x01, 0x00}: "ffdhe2048",
	[2]byte{0x01, 0x01}: "ffdhe3072",
	[2]byte{0x01, 0x02}: "ffdhe4096",
	[2]byte{0x01, 0x03}: "ffdhe6144",
	[2]byte{0x01, 0x04}: "ffdhe8192",
}

func namedgroupToName(ng [2]byte) string {
	s, ok := named_groups[ng]
	if !ok {
		return fmt.Sprintf("unknown (% X)", ng)
	}
	return s
}

// returns chunk, rest, ok
func getBytes(n int, data []byte) ([]byte, []byte, bool) {
	if n > len(data) {
		return nil, nil, false
	}
	return data[:n], data[n:], true
}

// returns chunk, rest, ok
func parseUint16Chunk(data []byte) ([]byte, []byte, bool) {
	if len(data) < 2 {
		return nil, nil, false
	}
	length := int(data[0])<<8 | int(data[1])
	if len(data) < 2+length {
		return nil, nil, false
	}
	chunk := data[2 : 2+length]
	return chunk, data[2+length:], true
}

type KeyShareEntry struct {
	group        [2]byte // NamedGroup
	key_exchange []byte  // opaque
}

type ESNIKeys struct {
	version        [2]byte
	checksum       [4]byte
	keys           []KeyShareEntry
	checksum_valid bool
	cipher_suites  [][2]byte
	padded_length  uint16
	not_before     uint64
	not_after      uint64
	extensions     []byte
}

func (k *ESNIKeys) Print(w io.Writer) {
	fmt.Fprintf(w, "version : % X ", k.version)
	if k.version == known_version {
		fmt.Fprintf(w, "(known)\n")
	} else {
		fmt.Fprintf(w, "(unknown)\n")
	}
	fmt.Fprintf(w, "checksum: % X ", k.checksum)
	if k.checksum_valid {
		fmt.Fprintf(w, "(valid)\n")
	} else {
		fmt.Fprintf(w, "(invalid)\n")
	}
	fmt.Fprintf(w, "keys (%d):\n", len(k.keys))
	for i, key := range k.keys {
		fmt.Fprintf(w, "  %d: %s [% X...]\n", i, namedgroupToName(key.group), key.key_exchange[:20])
	}
	fmt.Fprintf(w, "cipher_suites (%d):\n", len(k.cipher_suites))
	for i, cs := range k.cipher_suites {
		fmt.Fprintf(w, "  %d: %s\n", i, suiteToName(cs))
	}
	fmt.Fprintf(w, "padded_length: %d\n", k.padded_length)
	fmt.Fprintf(w, "not_before: %s\n", time.Unix(int64(k.not_before), 0))
	fmt.Fprintf(w, "not_after: %s\n", time.Unix(int64(k.not_after), 0))
	if len(k.extensions) > 0 {
		fmt.Fprintf(w, "extensions: % X\n", k.extensions)
	} else {
		fmt.Fprintln(w, "extensions: none")
	}
}

func parseESNIKeys(data []byte) (*ESNIKeys, error) {
	k := ESNIKeys{}
	b, rest, ok := getBytes(2, data)
	if !ok {
		return nil, fmt.Errorf("failed to parse version")
	}
	copy(k.version[:], b)

	c, rest, ok := getBytes(4, rest)
	if !ok {
		return nil, fmt.Errorf("failed to parse checksum")
	}
	copy(k.checksum[:], c)

	// now that we imported the checksum. zero it for checksumming
	copy(data[2:7], []byte{0, 0, 0, 0})
	sum := sha256.Sum256(data)
	if bytes.Equal(sum[0:4], k.checksum[:]) {
		k.checksum_valid = true
	}

	keys, rest, ok := parseUint16Chunk(rest)
	if !ok {
		return nil, fmt.Errorf("failed to parse keys")
	}
	rest_keys := keys
	for {
		ng, rest_keys, ok := getBytes(2, rest_keys)
		if !ok {
			return nil, fmt.Errorf("failed to parse NamedGroup")
		}
		key, rest_keys, ok := parseUint16Chunk(rest_keys)
		if !ok {
			return nil, fmt.Errorf("failed to parse key_exchange")
		}

		kse := KeyShareEntry{}
		copy(kse.group[:], ng)
		kse.key_exchange = key
		k.keys = append(k.keys, kse)

		if len(rest_keys) == 0 {
			break
		}
	}
	// TODO: validate that every key belongs to a different group

	cipher_suites, rest, ok := parseUint16Chunk(rest)
	if !ok {
		return nil, fmt.Errorf("failed to parse cipher_suites")
	}
	// ciphersuites come in two-byte chunks, so it must be an even number
	if len(cipher_suites)%2 != 0 {
		return nil, fmt.Errorf("cipher_suites_size must be an even number")
	}

	for i := 0; i < (len(cipher_suites) / 2); i++ {
		var a [2]byte
		copy(a[:], cipher_suites[i*2:i*2+2])
		k.cipher_suites = append(k.cipher_suites, a)
	}

	pl_bytes, rest, ok := getBytes(2, rest)
	if !ok {
		return nil, fmt.Errorf("failed to parse padded_length")
	}
	k.padded_length = binary.BigEndian.Uint16(pl_bytes)

	nb_bytes, rest, ok := getBytes(8, rest)
	if !ok {
		return nil, fmt.Errorf("failed to parse not_before")
	}
	k.not_before = binary.BigEndian.Uint64(nb_bytes)

	na_bytes, rest, ok := getBytes(8, rest)
	if !ok {
		return nil, fmt.Errorf("failed to parse not_after")
	}
	k.not_after = binary.BigEndian.Uint64(na_bytes)

	extensions, rest, ok := parseUint16Chunk(rest)
	if !ok {
		return nil, fmt.Errorf("failed to parse extensions")
	}
	copy(k.extensions, extensions)
	if len(rest) > 0 {
		return nil, fmt.Errorf("extra data at end of record")
	}
	return &k, nil
}

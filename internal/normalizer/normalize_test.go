package normalizer

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"testing"
)

const (
	testSHA  = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	testFile = "Logs/Security.evtx"
	testLoc  = "record=1234"
)

func TestUID(t *testing.T) {
	sum := sha256.Sum256([]byte(testSHA + "\x00" + testFile + "\x00" + testLoc))
	want := hex.EncodeToString(sum[:])[:32]
	got := UID(testSHA, testFile, testLoc)
	if got != want {
		t.Fatalf("UID = %s, want %s", got, want)
	}
	if !isLowerHex(got, 32) {
		t.Errorf("UID %q is not 32 lowercase hex characters", got)
	}
	for _, other := range []string{
		UID(testSHA[:63]+"0", testFile, testLoc),
		UID(testSHA, "Logs/System.evtx", testLoc),
		UID(testSHA, testFile, "record=1235"),
	} {
		if other == got {
			t.Errorf("UID unchanged when an input changes: %s", other)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	for _, c := range []struct{ raw, host, fqdn string }{
		{"WIN-77LTAPHIQ1R.example.corp", "WIN-77LTAPHIQ1R", "WIN-77LTAPHIQ1R.example.corp"},
		{"msedgewin10", "MSEDGEWIN10", ""},
		{" msedgewin10 ", "MSEDGEWIN10", ""},
		{"", "", ""},
	} {
		host, fqdn := NormalizeHost(c.raw)
		if host != c.host || fqdn != c.fqdn {
			t.Errorf("NormalizeHost(%q) = %q, %q; want %q, %q", c.raw, host, fqdn, c.host, c.fqdn)
		}
	}
}

func TestNewAccount(t *testing.T) {
	for _, c := range []struct {
		sid, domain, name string
		want              *Account
	}{
		{"-", "-", "-", nil},
		{"", "", "", nil},
		{"S-1-0-0", "", "", nil},
		{"s-1-5-18", "NT AUTHORITY", "SYSTEM", &Account{Domain: "NT AUTHORITY", Name: "SYSTEM", SID: "S-1-5-18"}},
		{"S-1-0-0", "EXAMPLE", "alice", &Account{Domain: "EXAMPLE", Name: "alice"}},
		{"S-1-5-21-1-2-3-1104", "-", "", &Account{SID: "S-1-5-21-1-2-3-1104"}},
	} {
		got := NewAccount(c.sid, c.domain, c.name)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("NewAccount(%q, %q, %q) = %+v, want %+v", c.sid, c.domain, c.name, got, c.want)
		}
	}
}

func TestFormatHex(t *testing.T) {
	for v, want := range map[uint64]string{0xc000006d: "0xc000006d", 0x3e7: "0x3e7", 0: "0x0"} {
		if got := FormatHex(v); got != want {
			t.Errorf("FormatHex(%d) = %q, want %q", v, got, want)
		}
	}
}

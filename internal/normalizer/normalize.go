package normalizer

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// UID calcule l'identifiant stable d'un enregistrement (FR-008) : il ne
// dépend que de la preuve et de la position de l'enregistrement.
func UID(sha256Hex, file, locator string) string {
	sum := sha256.Sum256([]byte(sha256Hex + "\x00" + file + "\x00" + locator))
	return hex.EncodeToString(sum[:16])
}

// NormalizeHost renvoie le nom court en majuscules et, si la valeur brute
// contient un ".", le FQDN tel quel (FR-012).
func NormalizeHost(raw string) (host, fqdn string) {
	short, _, dotted := strings.Cut(strings.TrimSpace(raw), ".")
	if dotted {
		fqdn = raw
	}
	return strings.ToUpper(short), fqdn
}

// NewAccount construit un compte en traitant "-", "" et le SID nul
// S-1-0-0 comme absents ; nil si rien ne reste (FR-011).
func NewAccount(sid, domain, name string) *Account {
	absent := func(s string) string {
		if s == "-" {
			return ""
		}
		return s
	}
	sid = strings.ToUpper(absent(sid))
	if sid == nullSID {
		sid = ""
	}
	a := Account{Domain: absent(domain), Name: absent(name), SID: sid}
	if a == (Account{}) {
		return nil
	}
	return &a
}

// FormatHex rend un entier comme Windows (HexInt32/HexInt64) : 0x + hexa minuscule.
func FormatHex(v uint64) string {
	return "0x" + strconv.FormatUint(v, 16)
}

const nullSID = "S-1-0-0"

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

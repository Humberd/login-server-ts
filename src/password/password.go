package password

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Shared with the game server (libargon2) and MyAAC (PHP PASSWORD_ARGON2ID).
const (
	memoryKiB  = 19456
	iterations = 2
	lanes      = 1
	saltLen    = 16
	keyLen     = 32

	maxMemoryKiB  = 262144
	maxIterations = 10
	maxLanes      = 8
	minSaltLen    = 8
	maxSaltLen    = 64
	minKeyLen     = 16
	maxKeyLen     = 64

	prefix = "$argon2id$"
)

type Result int

const (
	Mismatch Result = iota
	Match
	MatchLegacy
)

var b64 = base64.RawStdEncoding

var dummySalt = make([]byte, saltLen)

func Hash(plain string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(plain), salt, iterations, memoryKiB, lanes, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memoryKiB, iterations, lanes, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// Verify costs one argon2id run on every path so response time does not reveal
// whether an account exists or still has a legacy hash.
func Verify(plain, stored string) Result {
	if strings.HasPrefix(stored, prefix) {
		if verifyArgon2id(plain, stored) {
			return Match
		}
		return Mismatch
	}

	Burn(plain)

	if len(stored) == 2*sha1.Size {
		want, err := hex.DecodeString(stored)
		if err != nil {
			return Mismatch
		}
		got := sha1.Sum([]byte(plain))
		if subtle.ConstantTimeCompare(got[:], want) == 1 {
			return MatchLegacy
		}
	}
	return Mismatch
}

func Burn(plain string) {
	argon2.IDKey([]byte(plain), dummySalt, iterations, memoryKiB, lanes, keyLen)
}

type params struct {
	memory  uint32
	time    uint32
	threads uint8
	salt    []byte
	key     []byte
}

func verifyArgon2id(plain, stored string) bool {
	p, ok := parse(stored)
	if !ok {
		Burn(plain)
		return false
	}
	got := argon2.IDKey([]byte(plain), p.salt, p.time, p.memory, p.threads, uint32(len(p.key)))
	return subtle.ConstantTimeCompare(got, p.key) == 1
}

func parse(stored string) (params, bool) {
	var p params
	parts := strings.Split(stored, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return p, false
	}

	fields := strings.Split(parts[3], ",")
	if len(fields) != 3 {
		return p, false
	}
	m, okM := field(fields[0], "m=", maxMemoryKiB)
	t, okT := field(fields[1], "t=", maxIterations)
	l, okL := field(fields[2], "p=", maxLanes)
	if !okM || !okT || !okL || m < 8*l {
		return p, false
	}

	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) < minSaltLen || len(salt) > maxSaltLen {
		return p, false
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil || len(key) < minKeyLen || len(key) > maxKeyLen {
		return p, false
	}

	return params{memory: uint32(m), time: uint32(t), threads: uint8(l), salt: salt, key: key}, true
}

func field(s, name string, max uint64) (uint64, bool) {
	if !strings.HasPrefix(s, name) {
		return 0, false
	}
	v, err := strconv.ParseUint(s[len(name):], 10, 32)
	if err != nil || v < 1 || v > max {
		return 0, false
	}
	return v, true
}

package password

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// php -r 'echo password_hash("test", PASSWORD_ARGON2ID, ["memory_cost"=>19456,"time_cost"=>2,"threads"=>1]);'
const phpVector = "$argon2id$v=19$m=19456,t=2,p=1$TTNWdy9DOVcwVk5ISTFOTg$YEpzDGgMg4xBoYHgC58SVkZP+svlUAq8+sp3yXoCFcY"

func TestHashRoundTrip(t *testing.T) {
	hash, err := Hash("secret")
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(hash, "$argon2id$v=19$m=19456,t=2,p=1$"))
	parts := strings.Split(hash, "$")
	require.Len(t, parts, 6)
	assert.Len(t, parts[4], 22, "16-byte salt, unpadded base64")
	assert.Len(t, parts[5], 43, "32-byte key, unpadded base64")
	assert.LessOrEqual(t, len(hash), 255)
	assert.Equal(t, Match, Verify("secret", hash))
	assert.Equal(t, Mismatch, Verify("Secret", hash))

	other, err := Hash("secret")
	require.NoError(t, err)
	assert.NotEqual(t, hash, other)
}

func TestVerifyPHPVector(t *testing.T) {
	assert.Equal(t, Match, Verify("test", phpVector))
	assert.Equal(t, Mismatch, Verify("test2", phpVector))
}

func TestVerifyLegacySHA1(t *testing.T) {
	const god = "21298df8a3277357ee55b01df9530b535cf08ec1"
	assert.Equal(t, MatchLegacy, Verify("god", god))
	assert.Equal(t, MatchLegacy, Verify("god", strings.ToUpper(god)))
	assert.Equal(t, Mismatch, Verify("gods", god))
}

func TestVerifyRejectsGarbage(t *testing.T) {
	for _, stored := range []string{
		"",
		"god",
		"zz298df8a3277357ee55b01df9530b535cf08ec1",
		"21298df8a3277357ee55b01df9530b535cf08ec",
		"$argon2i$v=19$m=19456,t=2,p=1$TTNWdy9DOVcwVk5ISTFOTg$YEpzDGgMg4xBoYHgC58SVkZP+svlUAq8+sp3yXoCFcY",
		"$argon2id$v=16$m=19456,t=2,p=1$TTNWdy9DOVcwVk5ISTFOTg$YEpzDGgMg4xBoYHgC58SVkZP+svlUAq8+sp3yXoCFcY",
		"$argon2id$v=19$t=2,m=19456,p=1$TTNWdy9DOVcwVk5ISTFOTg$YEpzDGgMg4xBoYHgC58SVkZP+svlUAq8+sp3yXoCFcY",
		"$argon2id$v=19$m=19456,t=2,p=1$TTNWdy9DOVcwVk5ISTFOTg",
		"$argon2id$v=19$m=19456,t=2,p=1$!!!!$YEpzDGgMg4xBoYHgC58SVkZP+svlUAq8+sp3yXoCFcY",
		"$argon2id$v=19$m=19456,t=2,p=1$TTNWdy9DOVcwVk5ISTFOTg$",
		"$argon2id$v=19$m=19456,t=2,p=1$TTNWdy9DOVcwVk5ISTFOTg$YEpzDGgMg4xBoYHgC58SVkZP+svlUAq8+sp3yXoCFcY$x",
	} {
		assert.Equal(t, Mismatch, Verify("test", stored), stored)
	}
}

func TestVerifyRejectsParamsOutOfBounds(t *testing.T) {
	const tail = "$TTNWdy9DOVcwVk5ISTFOTg$YEpzDGgMg4xBoYHgC58SVkZP+svlUAq8+sp3yXoCFcY"
	for _, p := range []string{
		"m=262145,t=2,p=1",
		"m=19456,t=11,p=1",
		"m=19456,t=2,p=9",
		"m=0,t=2,p=1",
		"m=19456,t=0,p=1",
		"m=19456,t=2,p=0",
		"m=8,t=2,p=4",
		"m=-1,t=2,p=1",
		"m=19456,t=2",
	} {
		stored := "$argon2id$v=19$" + p + tail
		_, ok := parse(stored)
		assert.False(t, ok, stored)
		assert.Equal(t, Mismatch, Verify("test", stored), stored)
	}
}

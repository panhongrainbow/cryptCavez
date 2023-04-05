package aesz

import (
	"crypto/rand"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_Check_AESZ(t *testing.T) {
	//
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}

	//
	tests := []struct {
		plaintext []byte
	}{
		{
			[]byte("The best is yet to come."),
		},
		{
			[]byte("get over yourself"),
		},
	}
	//
	for i := 0; i < len(tests); i++ {
		encrypted, err := Encrypt(key, tests[i].plaintext)
		require.NoError(t, err)
		require.NotEqual(t, tests[i].plaintext, encrypted)
		decrypted, err := Decrypt(key, encrypted)
		require.NoError(t, err)
		require.Equal(t, tests[i].plaintext, decrypted)
	}
}

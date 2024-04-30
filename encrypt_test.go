package streambox_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/ozkatz/streambox"
)

func dataGen(t testing.TB, size int64) []byte {
	b := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		t.Fatalf("could not generate bytes: %v", err)
	}
	return b
}

func TestEncryptAndDecryptLoop(t *testing.T) {
	gen := func(size int64) func(t testing.TB) []byte {
		return func(t testing.TB) []byte {
			return dataGen(t, size)
		}
	}
	cases := []struct {
		Name       string
		InputBytes func(t testing.TB) []byte
		SecretKey  [32]byte
	}{
		{
			Name:       "very_small",
			InputBytes: gen(16),
			SecretKey:  [32]byte([]byte("12345678912345678912345678912345")),
		},
		{
			Name:       "exactly_one_page",
			InputBytes: gen(streambox.MessageSize),
			SecretKey:  [32]byte([]byte("12345678912345678912345678912345")),
		},
		{
			Name:       "more_than_one_page",
			InputBytes: gen(streambox.MessageSize + streambox.MessageSize/2),
			SecretKey:  [32]byte([]byte("12345678912345678912345678912345")),
		},
		{
			Name:       "many_pages",
			InputBytes: gen(streambox.MessageSize*5 + streambox.MessageSize/2),
			SecretKey:  [32]byte([]byte("12345678912345678912345678912345")),
		},
	}

	for _, cas := range cases {
		t.Run(cas.Name, func(t *testing.T) {
			originalData := cas.InputBytes(t)
			// encrypt
			enc := streambox.Encrypt(cas.SecretKey, bytes.NewReader(originalData))
			encryptedData, err := io.ReadAll(enc)
			if err != nil {
				t.Fatalf("error!")
			}

			// now decrypt!
			dec := streambox.Decrypt(cas.SecretKey, bytes.NewReader(encryptedData))
			decryptedData, err := io.ReadAll(dec)
			if err != nil {
				t.Fatalf("could not decrypt: %v", err)
			}
			if !bytes.Equal(decryptedData, originalData) {
				t.Fatalf("decrypted data differs from original!")
			}
		})
	}
}

func BenchmarkEncryptingReader(b *testing.B) {
	key := [32]byte([]byte("12345678912345678912345678912345"))
	data := dataGen(b, 1024*1024*256) // 256MB
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		buf := bytes.NewReader(data)
		enc := streambox.Encrypt(key, buf)
		b.StartTimer()
		b.SetBytes(int64(len(data)))
		if _, err := io.ReadAll(enc); err != nil {
			b.Fatalf("unexpected error consuming encrypted stream: %v", err)
		}
	}
}

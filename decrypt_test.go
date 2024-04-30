package streambox_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/ozkatz/streambox"
)

func TestReadInvalidDecryption(t *testing.T) {
	data := dataGen(t, 1024)
	enc := streambox.Encrypt(
		[32]byte([]byte("12341234123412341234123412341234")), bytes.NewReader(data))
	encrypted, err := io.ReadAll(enc)
	if err != nil {
		t.Fatalf("could not encrypt: %v", err)
	}

	// now decrypt with another key
	dec := streambox.Decrypt(
		[32]byte([]byte("12341234123412341234123412341235")), // see the different key there?
		bytes.NewReader(encrypted),
	)
	_, err = io.ReadAll(dec)
	if !errors.Is(err, streambox.ErrDecryptingMessage) {
		t.Fatalf("should not have been able to decrypt!")
	}
}

func BenchmarkDecryptingReader(b *testing.B) {
	key := [32]byte([]byte("12345678912345678912345678912345"))
	data := dataGen(b, 1024*1024*256) // 256MB
	buf := bytes.NewReader(data)
	enc := streambox.Encrypt(key, buf)
	encryptedBytes, err := io.ReadAll(enc)
	if err != nil {
		b.Fatalf("unexpected error consuming encrypted stream: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		buf = bytes.NewReader(encryptedBytes)
		dec := streambox.Decrypt(key, buf)
		b.StartTimer()
		b.SetBytes(int64(len(encryptedBytes)))
		if _, err := io.ReadAll(dec); err != nil {
			b.Fatalf("unexpected error consuming decrypting stream: %v", err)
		}
	}
}

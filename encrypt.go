package streambox

import (
	"crypto/rand"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	// MessageSize is set to 16KB messages, as recommended here:
	// https://pkg.go.dev/golang.org/x/crypto@v0.22.0/nacl/secretbox
	MessageSize = 16 * 1024
)

var _ io.Reader = &EncryptingReader{}

type EncryptingReader struct {
	SecretKey         [32]byte
	UnencryptedStream io.Reader

	buf []byte
}

func Encrypt(preSharedKey [32]byte, unencryptedStream io.Reader) *EncryptingReader {
	return &EncryptingReader{
		SecretKey:         preSharedKey,
		UnencryptedStream: unencryptedStream,
	}
}

func genNonce() ([24]byte, error) {
	var nonce [24]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])
	return nonce, err
}

func encryptMessage(secretKey [32]byte, unencryptedMessage []byte) ([]byte, error) {
	nonce, err := genNonce()
	if err != nil {
		return nil, err
	}
	return secretbox.Seal(nonce[:], unencryptedMessage, &nonce, &secretKey), nil
}

func (r *EncryptingReader) encryptNext() error {
	var eof bool
	p := make([]byte, MessageSize)
	n, err := r.UnencryptedStream.Read(p)
	if err == io.EOF && n == 0 {
		return io.EOF
	} else if err == io.EOF {
		eof = true
	} else if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	p = p[:n]
	encryptedMessage, err := encryptMessage(r.SecretKey, p)
	if err != nil {
		return err
	}
	sizer := make([]byte, 4)
	binary.BigEndian.PutUint32(sizer, uint32(len(encryptedMessage)))
	r.buf = append(r.buf, append(sizer, encryptedMessage...)...)
	if eof {
		return io.EOF
	}
	return nil
}

func (r *EncryptingReader) Read(p []byte) (int, error) {
	var err error
	for len(p) > len(r.buf) {
		// encrypt more stuff!
		err = r.encryptNext()
		if err == io.EOF {
			break
		} else if err != nil {
			return 0, err
		}
	}
	if len(r.buf) == 0 {
		return 0, io.EOF
	}
	// write into p
	size := len(p)
	if size > len(r.buf) {
		size = len(r.buf)
	}
	copy(p, r.buf[0:size])
	r.buf = r.buf[size:]
	return size, nil
}

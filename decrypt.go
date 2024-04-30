package streambox

import (
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

var (
	ErrDecryptingMessage = errors.New("could not decrypt message")
)

var _ io.Reader = &DecryptingReader{}

type DecryptingReader struct {
	SecretKey       [32]byte
	EncryptedStream io.Reader

	buf []byte
}

func Decrypt(preSharedKey [32]byte, encryptedStream io.Reader) *DecryptingReader {
	return &DecryptingReader{
		SecretKey:       preSharedKey,
		EncryptedStream: encryptedStream,
	}
}

func decryptMessage(secretKey [32]byte, encryptedMessage []byte) ([]byte, error) {
	var decryptNonce [24]byte
	copy(decryptNonce[:], encryptedMessage[:24])
	decrypted, ok := secretbox.Open(nil, encryptedMessage[24:], &decryptNonce, &secretKey)
	if !ok {
		return decrypted, ErrDecryptingMessage
	}
	return decrypted, nil
}

func (r *DecryptingReader) decryptNext() error {
	sizer := make([]byte, 4)
	if _, err := io.ReadAtLeast(r.EncryptedStream, sizer, len(sizer)); err == io.EOF {
		return io.EOF // no more messages
	} else if err != nil {
		return err
	}
	encrypted := make([]byte, binary.BigEndian.Uint32(sizer))
	if _, err := io.ReadAtLeast(r.EncryptedStream, encrypted, len(encrypted)); err != nil {
		return err
	}

	decryptedMessage, err := decryptMessage(r.SecretKey, encrypted)
	if err != nil {
		return err
	}
	r.buf = append(r.buf, decryptedMessage...)
	return nil
}

func (r *DecryptingReader) Read(p []byte) (int, error) {
	var err error
	for len(p) > len(r.buf) {
		// encrypt more stuff!
		err = r.decryptNext()
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

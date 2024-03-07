package pont

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type Suite string

const (
	ChaCha20_Poly1305 Suite = "ChaCha20-Poly1305"
	AES_256_GCM       Suite = "AES-256-GCM"
)

var seps = map[Suite]string{
	ChaCha20_Poly1305: "$",
	AES_256_GCM:       "#",
}

func Encrypt(suite Suite, key, plaintext, aad string) (ciphertext string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%+v", r)
		}
	}()
	switch suite {
	case AES_256_GCM:
		salt := make([]byte, 32)
		if _, err = rand.Read(salt); err != nil {
			return
		}
		dk := make([]byte, 32)
		if _, err = io.ReadFull(hkdf.New(sha512.New, []byte(key), salt, nil), dk); err != nil {
			return
		}
		var block cipher.Block
		if block, err = aes.NewCipher(dk); err != nil {
			return
		}
		var aead cipher.AEAD
		if aead, err = cipher.NewGCM(block); err != nil {
			return
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err = rand.Read(nonce); err != nil {
			return
		}
		sep := seps[suite]
		text := aead.Seal(nil, nonce, []byte(plaintext), []byte(aad))
		if len(aad) > 0 {
			ciphertext = fmt.Sprintf("%s%s%s%s%s%s%s", base64.StdEncoding.EncodeToString(salt), sep, base64.StdEncoding.EncodeToString(nonce), sep, base64.StdEncoding.EncodeToString(text), sep, aad)
		} else {
			ciphertext = fmt.Sprintf("%s%s%s%s%s", base64.StdEncoding.EncodeToString(salt), sep, base64.StdEncoding.EncodeToString(nonce), sep, base64.StdEncoding.EncodeToString(text))
		}
	case ChaCha20_Poly1305:
		salt := make([]byte, 32)
		if _, err = rand.Read(salt); err != nil {
			return
		}
		dk := make([]byte, chacha20poly1305.KeySize)
		if _, err = io.ReadFull(hkdf.New(sha512.New, []byte(key), salt, nil), dk); err != nil {
			return
		}
		var aead cipher.AEAD
		if aead, err = chacha20poly1305.New(dk); err != nil {
			return
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err = rand.Read(nonce); err != nil {
			return
		}
		sep := seps[suite]
		text := aead.Seal(nil, nonce, []byte(plaintext), []byte(aad))
		if len(aad) > 0 {
			ciphertext = fmt.Sprintf("%s%s%s%s%s%s%s", base64.StdEncoding.EncodeToString(salt), sep, base64.StdEncoding.EncodeToString(nonce), sep, base64.StdEncoding.EncodeToString(text), sep, aad)
		} else {
			ciphertext = fmt.Sprintf("%s%s%s%s%s", base64.StdEncoding.EncodeToString(salt), sep, base64.StdEncoding.EncodeToString(nonce), sep, base64.StdEncoding.EncodeToString(text))
		}
	default:
		err = errors.ErrUnsupported
	}
	return
}

func Decrypt(key, ciphertext string) (suite Suite, plaintext, aad string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%+v", r)
		}
	}()
	err = errors.ErrUnsupported
	if v := strings.Split(ciphertext, seps[AES_256_GCM]); len(v) >= 3 {
		suite = AES_256_GCM
		sep := seps[AES_256_GCM]
		var salt []byte
		if salt, err = base64.StdEncoding.DecodeString(v[0]); err != nil {
			return
		}
		var nonce []byte
		if nonce, err = base64.StdEncoding.DecodeString(v[1]); err != nil {
			return
		}
		var text []byte
		if text, err = base64.StdEncoding.DecodeString(v[2]); err != nil {
			return
		}
		if len(v) > 3 {
			aad = strings.Join(v[3:], sep)
		}
		dk := make([]byte, 32)
		if _, err = io.ReadFull(hkdf.New(sha512.New, []byte(key), salt, nil), dk); err != nil {
			return
		}
		var block cipher.Block
		if block, err = aes.NewCipher(dk); err != nil {
			return
		}
		var aead cipher.AEAD
		if aead, err = cipher.NewGCM(block); err != nil {
			return
		}
		if text, err = aead.Open(nil, nonce, text, []byte(aad)); err != nil {
			return
		}
		plaintext = string(text)
	} else if v := strings.Split(ciphertext, seps[ChaCha20_Poly1305]); len(v) >= 3 {
		suite = ChaCha20_Poly1305
		sep := seps[ChaCha20_Poly1305]
		var salt []byte
		if salt, err = base64.StdEncoding.DecodeString(v[0]); err != nil {
			return
		}
		var nonce []byte
		if nonce, err = base64.StdEncoding.DecodeString(v[1]); err != nil {
			return
		}
		var text []byte
		if text, err = base64.StdEncoding.DecodeString(v[2]); err != nil {
			return
		}
		if len(v) > 3 {
			aad = strings.Join(v[3:], sep)
		}
		dk := make([]byte, chacha20poly1305.KeySize)
		if _, err = io.ReadFull(hkdf.New(sha512.New, []byte(key), salt, nil), dk); err != nil {
			return
		}
		var aead cipher.AEAD
		if aead, err = chacha20poly1305.New(dk); err != nil {
			return
		}
		if text, err = aead.Open(nil, nonce, text, []byte(aad)); err != nil {
			return
		}
		plaintext = string(text)
	}
	return
}

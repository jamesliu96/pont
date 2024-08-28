package pont

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

type Suite string

const (
	ChaCha20_Poly1305_SHA256   Suite = "ChaCha20-Poly1305_SHA256"
	ChaCha20_Poly1305_SHA3_256 Suite = "ChaCha20-Poly1305_SHA3-256"
	AES_256_GCM_SHA256         Suite = "AES-256-GCM_SHA256"
	AES_256_GCM_SHA3_256       Suite = "AES-256-GCM_SHA3-256"
)

const saltSize = 32

var seps = map[Suite]string{
	ChaCha20_Poly1305_SHA256:   "$",
	ChaCha20_Poly1305_SHA3_256: ":",
	AES_256_GCM_SHA256:         "#",
	AES_256_GCM_SHA3_256:       "@",
}

var keySizes = map[Suite]int{
	ChaCha20_Poly1305_SHA256:   chacha20poly1305.KeySize,
	ChaCha20_Poly1305_SHA3_256: chacha20poly1305.KeySize,
	AES_256_GCM_SHA256:         32,
	AES_256_GCM_SHA3_256:       32,
}

var aes256 = func(dk []byte) (aead cipher.AEAD, err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(dk); err != nil {
		return
	}
	aead, err = cipher.NewGCM(block)
	return
}
var aeads = map[Suite]func([]byte) (cipher.AEAD, error){
	ChaCha20_Poly1305_SHA256:   chacha20poly1305.New,
	ChaCha20_Poly1305_SHA3_256: chacha20poly1305.New,
	AES_256_GCM_SHA256:         aes256,
	AES_256_GCM_SHA3_256:       aes256,
}

var encoding = base64.RawStdEncoding

func Encrypt(suite Suite, key, plaintext, aad string) (ciphertext string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%+v", r)
		}
	}()
	err = errors.ErrUnsupported
	switch suite {
	case ChaCha20_Poly1305_SHA256, AES_256_GCM_SHA256:
		ciphertext, err = encrypt(suite, key, plaintext, aad, sha256.New)
	case ChaCha20_Poly1305_SHA3_256, AES_256_GCM_SHA3_256:
		ciphertext, err = encrypt(suite, key, plaintext, aad, sha3.New256)
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
	if v := strings.Split(ciphertext, seps[ChaCha20_Poly1305_SHA256]); len(v) >= 3 {
		suite = ChaCha20_Poly1305_SHA256
		plaintext, aad, err = decrypt(suite, v, key, sha256.New)
	} else if v := strings.Split(ciphertext, seps[AES_256_GCM_SHA256]); len(v) >= 3 {
		suite = AES_256_GCM_SHA256
		plaintext, aad, err = decrypt(suite, v, key, sha256.New)
	} else if v := strings.Split(ciphertext, seps[ChaCha20_Poly1305_SHA3_256]); len(v) >= 3 {
		suite = ChaCha20_Poly1305_SHA3_256
		plaintext, aad, err = decrypt(suite, v, key, sha3.New256)
	} else if v := strings.Split(ciphertext, seps[AES_256_GCM_SHA3_256]); len(v) >= 3 {
		suite = AES_256_GCM_SHA3_256
		plaintext, aad, err = decrypt(suite, v, key, sha3.New256)
	}
	return
}

func encrypt(suite Suite, key, plaintext, aad string, h func() hash.Hash) (ciphertext string, err error) {
	salt := make([]byte, saltSize)
	if _, err = rand.Read(salt); err != nil {
		return
	}
	var dk []byte
	if dk, err = deriveKey(key, salt, h, keySizes[suite]); err != nil {
		return
	}
	var aead cipher.AEAD
	if aead, err = aeads[suite](dk); err != nil {
		return
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return
	}
	sep := seps[suite]
	text := aead.Seal(nil, nonce, []byte(plaintext), []byte(aad))
	if len(aad) > 0 {
		ciphertext = fmt.Sprintf("%s%s%s%s%s%s%s", encoding.EncodeToString(salt), sep, encoding.EncodeToString(nonce), sep, encoding.EncodeToString(text), sep, aad)
	} else {
		ciphertext = fmt.Sprintf("%s%s%s%s%s", encoding.EncodeToString(salt), sep, encoding.EncodeToString(nonce), sep, encoding.EncodeToString(text))
	}
	return
}

func decrypt(suite Suite, v []string, key string, h func() hash.Hash) (plaintext, aad string, err error) {
	var salt []byte
	if salt, err = encoding.DecodeString(v[0]); err != nil {
		return
	}
	var nonce []byte
	if nonce, err = encoding.DecodeString(v[1]); err != nil {
		return
	}
	var text []byte
	if text, err = encoding.DecodeString(v[2]); err != nil {
		return
	}
	if len(v) > 3 {
		aad = strings.Join(v[3:], seps[suite])
	}
	var dk []byte
	if dk, err = deriveKey(key, salt, h, keySizes[suite]); err != nil {
		return
	}
	var aead cipher.AEAD
	if aead, err = aeads[suite](dk); err != nil {
		return
	}
	if text, err = aead.Open(nil, nonce, text, []byte(aad)); err != nil {
		return
	}
	plaintext = string(text)
	return
}

func deriveKey(key string, salt []byte, h func() hash.Hash, size int) ([]byte, error) {
	dk := make([]byte, size)
	if _, err := io.ReadFull(hkdf.New(h, []byte(key), salt, nil), dk); err != nil {
		return nil, err
	}
	return dk, nil
}

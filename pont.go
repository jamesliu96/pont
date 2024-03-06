package main

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
	"syscall/js"

	"github.com/jamesliu96/ego"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type Suite string

const (
	AES_256_GCM       Suite = "AES-256-GCM"
	ChaCha20_Poly1305 Suite = "ChaCha20-Poly1305"
)

func deriveKey(key string, salt []byte) ([]byte, error) {
	dk := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha512.New, []byte(key), salt, nil), dk); err != nil {
		return nil, errors.ErrUnsupported
	}
	return dk, nil
}

func encrypt(suite Suite, key, plaintext, aad string) (ciphertext string, err error) {
	salt := make([]byte, 32)
	if _, err = rand.Read(salt); err != nil {
		return
	}
	var dk []byte
	if dk, err = deriveKey(key, salt); err != nil {
		return
	}
	switch suite {
	case AES_256_GCM:
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
		text := aead.Seal(nil, nonce, []byte(plaintext), []byte(aad))
		if len(aad) > 0 {
			ciphertext = fmt.Sprintf("%s|%s|%s|%s", base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(text), aad)
		} else {
			ciphertext = fmt.Sprintf("%s|%s|%s", base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(text))
		}
	case ChaCha20_Poly1305:
		var aead cipher.AEAD
		if aead, err = chacha20poly1305.New(dk); err != nil {
			return
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err = rand.Read(nonce); err != nil {
			return
		}
		text := aead.Seal(nil, nonce, []byte(plaintext), []byte(aad))
		if len(aad) > 0 {
			ciphertext = fmt.Sprintf("%s$%s$%s$%s", base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(text), aad)
		} else {
			ciphertext = fmt.Sprintf("%s$%s$%s", base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(text))
		}
	default:
		err = errors.ErrUnsupported
	}
	return
}

func decrypt(key, ciphertext string) (suite Suite, plaintext, aad string, err error) {
	err = errors.ErrUnsupported
	if v := strings.Split(ciphertext, "|"); len(v) >= 3 {
		suite = AES_256_GCM
		var salt []byte
		if salt, err = base64.StdEncoding.DecodeString(v[0]); err != nil {
			return
		}
		var nonce []byte
		if nonce, err = base64.StdEncoding.DecodeString(v[1]); err != nil {
			return
		}
		var dk []byte
		if dk, err = deriveKey(key, salt); err != nil {
			return
		}
		var text []byte
		if text, err = base64.StdEncoding.DecodeString(v[2]); err != nil {
			return
		}
		if len(v) > 3 {
			aad = strings.Join(v[3:], "|")
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
	}
	if v := strings.Split(ciphertext, "$"); len(v) >= 3 {
		suite = ChaCha20_Poly1305
		var salt []byte
		if salt, err = base64.StdEncoding.DecodeString(v[0]); err != nil {
			return
		}
		var nonce []byte
		if nonce, err = base64.StdEncoding.DecodeString(v[1]); err != nil {
			return
		}
		var dk []byte
		if dk, err = deriveKey(key, salt); err != nil {
			return
		}
		var text []byte
		if text, err = base64.StdEncoding.DecodeString(v[2]); err != nil {
			return
		}
		if len(v) > 3 {
			aad = strings.Join(v[3:], "$")
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

func main() {
	// function pont$$encrypt(suite: 1 | 2, key: string, plaintext: string, aad: string): Promise<string>
	js.Global().Set("pont$$encrypt", ego.PromiseOf(func(this js.Value, args []js.Value) any {
		suite, key, plaintext, aad := args[0].String(), args[1].String(), args[2].String(), args[3].String()
		ciphertext, err := encrypt(Suite(suite), key, plaintext, aad)
		if err != nil {
			panic(err)
		}
		return ciphertext
	}))

	// function pont$$decrypt(key: string, ciphertext: string): Promise<{ suite: 0 | 1; plaintext: string; aad: string }>
	js.Global().Set("pont$$decrypt", ego.PromiseOf(func(this js.Value, args []js.Value) any {
		key, ciphertext := args[0].String(), args[1].String()
		suite, plaintext, aad, err := decrypt(key, ciphertext)
		if err != nil {
			panic(err)
		}
		return map[string]any{"suite": string(suite), "plaintext": plaintext, "aad": aad}
	}))

	js.Global().Call("postMessage", map[string]any{"$$": true})

	ego.KeepAlive()
}

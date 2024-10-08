package main

import (
	"syscall/js"

	"github.com/jamesliu96/ego"
	"github.com/jamesliu96/pont"
)

func main() {
	// function pont$$encrypt(suite: string, key: string, plaintext: string, aad: string): Promise<string>
	js.Global().Set("pont$$encrypt", ego.AsyncFuncOf(func(this js.Value, args []js.Value) any {
		suite, key, plaintext, aad := args[0].String(), args[1].String(), args[2].String(), args[3].String()
		ciphertext, err := pont.Encrypt(pont.Suite(suite), key, plaintext, aad)
		if err != nil {
			panic(err)
		}
		return ciphertext
	}))

	// function pont$$decrypt(key: string, ciphertext: string): Promise<{ suite: string; plaintext: string; aad: string }>
	js.Global().Set("pont$$decrypt", ego.AsyncFuncOf(func(this js.Value, args []js.Value) any {
		key, ciphertext := args[0].String(), args[1].String()
		suite, plaintext, aad, err := pont.Decrypt(key, ciphertext)
		if err != nil {
			panic(err)
		}
		return map[string]any{"suite": string(suite), "plaintext": plaintext, "aad": aad}
	}))

	js.Global().Call("postMessage", map[string]any{"$$": []any{
		string(pont.ChaCha20_Poly1305_SHA256),
		string(pont.ChaCha20_Poly1305_SHA512),
		string(pont.ChaCha20_Poly1305_SHA3_256),
		string(pont.ChaCha20_Poly1305_SHA3_512),
		string(pont.AES_256_GCM_SHA256),
		string(pont.AES_256_GCM_SHA512),
		string(pont.AES_256_GCM_SHA3_256),
		string(pont.AES_256_GCM_SHA3_512),
	}})

	ego.KeepAlive()
}

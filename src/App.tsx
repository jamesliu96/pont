import { useCallback, useState } from 'react';

import './App.css';

function utf8_to_b64(str: string) {
  return window.btoa(unescape(encodeURIComponent(str)));
}
function b64_to_utf8(str: string) {
  return decodeURIComponent(escape(window.atob(str)));
}

function encodeText(str: string) {
  return new TextEncoder().encode(str);
}
function decodeText(bin: BufferSource) {
  return new TextDecoder().decode(bin);
}

function encode(str: string) {
  return Uint8Array.from([...str].map((c) => c.charCodeAt(0)));
}
function decode(bin: Uint8Array) {
  return String.fromCharCode(...bin);
}

const KDF = 'PBKDF2';
const CIPHER = 'AES-GCM';
const CIPHER_LENGTH = 256;
const ITERATIONS = 1000000;
const HASH = 'SHA-256';

function App() {
  const [wait, setWait] = useState(false);
  const [focus, setFocus] = useState(false);

  const [passcode, setPasscode] = useState('');

  const [plainText, setPlainText] = useState('');

  const [cipherText, setCipherText] = useState('');

  const encrypt = useCallback(async () => {
    setWait(true);
    try {
      const plain = encodeText(plainText);
      const salt = crypto.getRandomValues(new Uint8Array(32));
      const iv = crypto.getRandomValues(new Uint8Array(16));
      const key = await crypto.subtle.deriveKey(
        {
          name: KDF,
          salt,
          iterations: ITERATIONS,
          hash: HASH,
        },
        await crypto.subtle.importKey(
          'raw',
          encodeText(passcode),
          { name: KDF },
          false,
          ['deriveKey']
        ),
        { name: CIPHER, length: CIPHER_LENGTH },
        true,
        ['encrypt']
      );
      const cipher = await crypto.subtle.encrypt(
        { name: CIPHER, iv },
        key,
        plain
      );
      setCipherText(
        `${utf8_to_b64(decode(salt))}|${utf8_to_b64(decode(iv))}|${utf8_to_b64(
          decode(new Uint8Array(cipher))
        )}`
      );
    } catch (e) {
      alert(e);
      console.error(e);
    } finally {
      setWait(false);
    }
  }, [passcode, plainText]);

  const decrypt = useCallback(async () => {
    setWait(true);
    try {
      const [_salt, _iv = '', _cipher = ''] = cipherText.split('|');
      const salt = encode(b64_to_utf8(_salt));
      const iv = encode(b64_to_utf8(_iv));
      const cipher = encode(b64_to_utf8(_cipher));
      const key = await crypto.subtle.deriveKey(
        {
          name: KDF,
          salt,
          iterations: ITERATIONS,
          hash: HASH,
        },
        await crypto.subtle.importKey(
          'raw',
          encodeText(passcode),
          { name: KDF },
          false,
          ['deriveKey']
        ),
        { name: CIPHER, length: CIPHER_LENGTH },
        true,
        ['decrypt']
      );
      const plain = await crypto.subtle.decrypt(
        { name: CIPHER, iv },
        key,
        cipher
      );
      setPlainText(decodeText(plain));
    } catch (e) {
      alert(e);
      console.error(e);
    } finally {
      setWait(false);
    }
  }, [passcode, cipherText]);

  return (
    <div className="App">
      <input
        placeholder="passcode"
        type={focus ? 'text' : 'password'}
        value={passcode}
        onChange={(e) => {
          setPasscode(e.target.value);
        }}
        onFocus={() => {
          setFocus(true);
        }}
        onBlur={() => {
          setFocus(false);
        }}
      />
      <textarea
        placeholder="plain text"
        value={plainText}
        onChange={(e) => {
          setPlainText(e.target.value);
        }}
      />
      <div>
        <button onClick={encrypt}>Encrypt</button>
        <button onClick={decrypt}>Decrypt</button>
      </div>
      <textarea
        placeholder="cipher text"
        value={cipherText}
        onChange={(e) => {
          setCipherText(e.target.value);
        }}
      />
      {wait ? <div className="wait">wait...</div> : null}
    </div>
  );
}

export default App;

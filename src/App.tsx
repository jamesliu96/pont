import { useCallback, useEffect, useMemo, useState } from 'react';

import './App.css';

const encodeText = (str: string) => new TextEncoder().encode(str);
const decodeText = (bin: BufferSource) => new TextDecoder().decode(bin);

const utf8_to_b64 = (str: string) =>
  btoa(
    encodeURIComponent(str).replace(/%([\da-f]{2})/gi, (_, p) =>
      String.fromCharCode(parseInt(p, 16))
    )
  );
const b64_to_utf8 = (str: string) =>
  decodeURIComponent(
    [...atob(str)]
      .map((v) => `%${v.charCodeAt(0).toString(16).padStart(2, '0')}`)
      .join('')
  );

const encodeBin = (str: string) =>
  Uint8Array.from([...b64_to_utf8(str)].map((v) => v.charCodeAt(0)));
const decodeBin = (bin: Uint8Array) => utf8_to_b64(String.fromCharCode(...bin));

const hex_to_ascii = (hex: string) => {
  if (!hex.length || hex.length % 2) return '';
  let ascii = '';
  for (let idx = 0; idx < hex.length; idx += 2)
    ascii += String.fromCharCode(parseInt(hex.slice(idx, idx + 2), 16));
  return ascii;
};

const parseCipherText = (cipherText: string) => {
  const [_salt, _iv = '', _cipher = ''] = cipherText.split('|');
  const salt = encodeBin(_salt);
  const iv = encodeBin(_iv);
  const cipher = encodeBin(_cipher);
  return { salt, iv, cipher };
};

const copy = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text);
  } catch {}
};
const paste = async () => {
  try {
    return await navigator.clipboard.readText();
  } catch {}
};

const CIPHER = 'AES-GCM';
const CIPHER_LENGTH = 256;
const PBKDF2 = 'PBKDF2';
const PBKDF2_ITERATIONS = 1e6;
const HKDF = 'HKDF';
const HASH = 'SHA-256';

const App = () => {
  const [wait, setWait] = useState(false);
  const [focus, setFocus] = useState(false);

  const [passcode, setPasscode] = useState('');

  const [plainText, setPlainText] = useState('');
  const [cipherText, setCipherText] = useState('');

  const [sync, setSync] = useState(false);
  useEffect(() => {
    setSync(false);
  }, [passcode]);

  const [shared, setShared] = useState(false);
  const kdf = useMemo(() => (shared ? HKDF : PBKDF2), [shared]);

  const encrypt = useCallback(async () => {
    setWait(true);
    try {
      const salt = crypto.getRandomValues(new Uint8Array(32));
      const iv = crypto.getRandomValues(new Uint8Array(16));
      const text = [
        decodeBin(salt),
        decodeBin(iv),
        decodeBin(
          new Uint8Array(
            await crypto.subtle.encrypt(
              { name: CIPHER, iv },
              await crypto.subtle.deriveKey(
                kdf === 'HKDF'
                  ? { name: HKDF, hash: HASH, info: encodeText('PONT'), salt }
                  : {
                      name: PBKDF2,
                      hash: HASH,
                      iterations: PBKDF2_ITERATIONS,
                      salt,
                    },
                await crypto.subtle.importKey(
                  'raw',
                  encodeText(passcode),
                  kdf,
                  false,
                  ['deriveKey']
                ),
                { name: CIPHER, length: CIPHER_LENGTH },
                false,
                ['encrypt']
              ),
              encodeText(plainText)
            )
          )
        ),
      ].join('|');
      setCipherText(text);
      setSync(true);
      await copy(text);
    } catch (e) {
      console.error(e);
      alert(e);
    } finally {
      setWait(false);
    }
  }, [kdf, passcode, plainText]);

  const decrypt = useCallback(async () => {
    setWait(true);
    try {
      const { salt, iv, cipher } = parseCipherText(cipherText);
      setPlainText(
        decodeText(
          await crypto.subtle.decrypt(
            { name: CIPHER, iv },
            await crypto.subtle.deriveKey(
              kdf === 'HKDF'
                ? { name: HKDF, hash: HASH, info: encodeText('PONT'), salt }
                : {
                    name: PBKDF2,
                    hash: HASH,
                    iterations: PBKDF2_ITERATIONS,
                    salt,
                  },
              await crypto.subtle.importKey(
                'raw',
                encodeText(passcode),
                kdf,
                false,
                ['deriveKey']
              ),
              { name: CIPHER, length: CIPHER_LENGTH },
              false,
              ['decrypt']
            ),
            cipher
          )
        )
      );
      setSync(true);
    } catch (e) {
      console.error(e);
      alert(e);
    } finally {
      setWait(false);
    }
  }, [cipherText, kdf, passcode]);

  const handleFocus = useCallback(async () => {
    try {
      const text = await paste();
      if (text) {
        const { salt, iv, cipher } = parseCipherText(text);
        if (salt.length && iv.length && cipher.length) setCipherText(text);
      }
    } catch {}
  }, []);

  useEffect(() => {
    const handleMessage = ({
      data,
    }: MessageEvent<{ hex?: string; bin?: string } | undefined>) => {
      if (data?.bin) {
        setPasscode(data.bin);
        setShared(true);
      } else if (data?.hex) {
        setPasscode(hex_to_ascii(data.hex));
        setShared(true);
      }
    };
    window.addEventListener('message', handleMessage);
    return () => {
      window.removeEventListener('message', handleMessage);
    };
  }, []);

  return (
    <div className="App">
      <main>
        <section>
          <iframe
            title="xp"
            src="//geheim.jamesliu.info/xp/"
            allow="clipboard-read *; clipboard-write *"
          />
        </section>
        <section>
          <input
            disabled={wait}
            placeholder="passcode"
            type={shared ? 'password' : focus ? 'text' : 'password'}
            value={passcode}
            style={{ color: sync ? 'green' : shared ? 'blue' : undefined }}
            onChange={(e) => {
              setPasscode(e.target.value);
              setShared(false);
            }}
            onFocus={() => {
              setFocus(true);
            }}
            onBlur={() => {
              setFocus(false);
            }}
          />
        </section>
        <section>
          <textarea
            rows={5}
            disabled={wait}
            placeholder="plain text"
            value={plainText}
            style={{ color: sync ? 'green' : undefined }}
            onChange={(e) => {
              setPlainText(e.target.value);
              setSync(false);
            }}
          />
        </section>
        <section>
          <button disabled={wait} onClick={encrypt}>
            Encrypt
          </button>
          <button disabled={wait} onClick={decrypt}>
            Decrypt
          </button>
        </section>
        <section>
          <textarea
            rows={10}
            disabled={wait}
            spellCheck={false}
            placeholder="cipher text"
            value={cipherText}
            style={{ color: sync ? 'green' : undefined }}
            onChange={(e) => {
              setCipherText(e.target.value);
              setSync(false);
            }}
            onFocus={handleFocus}
          />
        </section>
      </main>
      <footer>
        <div>powered by</div>
        <div>
          The{' '}
          <a
            href="https://www.w3.org/TR/WebCryptoAPI/"
            target="_blank"
            rel="noreferrer"
          >
            Web Crypto API
          </a>
        </div>
        <div>and</div>
        <div>
          <a
            href="https://geheim.jamesliu.info"
            target="_blank"
            rel="noreferrer"
          >
            geheim
          </a>
        </div>
      </footer>
      <footer>
        <div>
          <a
            href="https://github.com/jamesliu96/pont"
            target="_blank"
            rel="noreferrer"
          >
            🌁
          </a>
        </div>
      </footer>
    </div>
  );
};

export default App;

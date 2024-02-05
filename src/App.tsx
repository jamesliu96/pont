import { useCallback, useEffect, useMemo, useState } from 'react';

import './App.css';

const [TE, TD] = [new TextEncoder(), new TextDecoder()];
const [encodeText, decodeText] = [
  (str: string) => TE.encode(str),
  (bin: BufferSource) => TD.decode(bin),
];

const [encodeBase64, decodeBase64] = [
  (bin: Uint8Array) => btoa(String.fromCodePoint(...bin)),
  (str: string) =>
    Uint8Array.from(atob(str), (v) => v.codePointAt(0) as number),
];

const [copy, paste] = [
  async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {}
  },
  async () => {
    try {
      return await navigator.clipboard.readText();
    } catch {}
  },
];

const parseCipherText = (cipherText: string) => {
  const [_salt, _iv = '', _cipher = '', aad = undefined] =
    cipherText.split('|');
  const salt = decodeBase64(_salt);
  const iv = decodeBase64(_iv);
  const cipher = decodeBase64(_cipher);
  return { salt, iv, cipher, aad };
};

const CIPHER = 'AES-GCM';
const CIPHER_LENGTH = 256;
const PBKDF2 = 'PBKDF2';
const PBKDF2_ITERATIONS = 1e6;
const HKDF = 'HKDF';
const HKDF_INFO = new Uint8Array();
const HASH = 'SHA-512';

const App = () => {
  const [wait, setWait] = useState(false);
  const [focus, setFocus] = useState(false);
  const [sync, setSync] = useState(false);

  const [passcode, setPasscode] = useState('');

  const [plaintext, setPlaintext] = useState('');
  const [ciphertext, setCiphertext] = useState('');

  const [aad, setAAD] = useState('');

  const [shared, setShared] = useState(false);
  const kdf = useMemo(() => (shared ? HKDF : PBKDF2), [shared]);

  const encrypt = useCallback(async () => {
    setWait(true);
    try {
      const salt = crypto.getRandomValues(new Uint8Array(32));
      const iv = crypto.getRandomValues(new Uint8Array(16));
      const text = [
        encodeBase64(salt),
        encodeBase64(iv),
        encodeBase64(
          new Uint8Array(
            await crypto.subtle.encrypt(
              {
                name: CIPHER,
                iv,
                ...(aad ? { additionalData: encodeText(aad) } : undefined),
              },
              await crypto.subtle.deriveKey(
                kdf === 'HKDF'
                  ? {
                      name: HKDF,
                      hash: HASH,
                      info: HKDF_INFO,
                      salt,
                    }
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
              encodeText(plaintext)
            )
          )
        ),
        aad,
      ]
        .slice(0, aad ? undefined : 3)
        .join('|');
      setCiphertext(text);
      setSync(true);
      await copy(text);
    } catch (e) {
      console.error(e);
      alert(e);
    } finally {
      setWait(false);
    }
  }, [aad, kdf, passcode, plaintext]);

  const decrypt = useCallback(async () => {
    setWait(true);
    try {
      const { salt, iv, cipher, aad } = parseCipherText(ciphertext);
      setPlaintext(
        decodeText(
          await crypto.subtle.decrypt(
            {
              name: CIPHER,
              iv,
              ...(aad ? { additionalData: encodeText(aad) } : undefined),
            },
            await crypto.subtle.deriveKey(
              kdf === 'HKDF'
                ? {
                    name: HKDF,
                    hash: HASH,
                    info: HKDF_INFO,
                    salt,
                  }
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
      if (aad) setAAD(aad);
      setSync(true);
    } catch (e) {
      console.error(e);
      alert(e);
    } finally {
      setWait(false);
    }
  }, [ciphertext, kdf, passcode]);

  const handleFocus = useCallback(async () => {
    try {
      const text = await paste();
      if (text) {
        const { salt, iv, cipher } = parseCipherText(text);
        if (salt.length && iv.length && cipher.length) setCiphertext(text);
      }
    } catch {}
  }, []);

  useEffect(() => {
    const handleMessage = ({
      data,
    }: MessageEvent<{ bin?: unknown } | undefined>) => {
      if (typeof data?.bin === 'string' && data.bin) {
        setPasscode(data.bin);
        setShared(true);
        setSync(false);
      }
    };
    window.addEventListener('message', handleMessage);
    return () => {
      window.removeEventListener('message', handleMessage);
    };
  }, []);

  const x = useMemo(
    () => (sync ? (shared ? '🔐' : '🔒') : shared ? '🔑' : '🔓'),
    [shared, sync]
  );

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
            title="passcode or key"
            placeholder="passcode"
            type={shared ? 'password' : focus ? 'text' : 'password'}
            value={passcode}
            style={{ color: sync ? 'green' : shared ? 'blue' : undefined }}
            onChange={(e) => {
              setPasscode(e.target.value);
              setShared(false);
              setSync(false);
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
            title="plaintext"
            placeholder="plaintext"
            value={plaintext}
            style={{ color: sync ? 'green' : undefined }}
            onChange={(e) => {
              setPlaintext(e.target.value);
              setSync(false);
            }}
          />
        </section>
        <section>
          <textarea
            rows={1}
            disabled={wait}
            title="additional authenticated data"
            placeholder="aad"
            value={aad}
            style={{ color: sync ? 'green' : undefined }}
            onChange={(e) => {
              setAAD(e.target.value);
              setSync(false);
            }}
          />
        </section>
        <section>
          <button
            disabled={wait}
            style={{ color: sync ? 'green' : undefined }}
            onClick={encrypt}
          >
            Encrypt
          </button>
          <div
            style={{ cursor: 'pointer' }}
            onClick={() => {
              setShared((x) => !x);
              setSync(false);
            }}
          >
            {x}
          </div>
          <button
            disabled={wait}
            style={{ color: sync ? 'green' : undefined }}
            onClick={decrypt}
          >
            Decrypt
          </button>
        </section>
        <section>
          <textarea
            rows={10}
            disabled={wait}
            spellCheck={false}
            title="ciphertext"
            placeholder="ciphertext"
            value={ciphertext}
            style={{ color: sync ? 'green' : undefined }}
            onChange={(e) => {
              setCiphertext(e.target.value);
              setSync(false);
            }}
            onFocus={handleFocus}
          />
        </section>
      </main>
      <footer style={{ marginTop: '2em' }}>
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
      <footer style={{ marginTop: '1em' }}>
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

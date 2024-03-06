import {
  CSSProperties,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react';

import './App.css';

import './wasm_exec.js';

const [encodeRaw] = [
  (str: string) => Uint8Array.from(str, (v) => v.charCodeAt(0)),
  (bin: Uint8Array) => String.fromCharCode(...bin),
];

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

const SPLITTER = '|';

const [wrapCipher, unwrapCipher] = [
  (
    salt: Uint8Array,
    nonce: Uint8Array,
    text: Uint8Array,
    aad: string | undefined
  ) =>
    [
      encodeBase64(salt),
      encodeBase64(nonce),
      encodeBase64(text),
      ...(aad ? [aad] : []),
    ].join(SPLITTER),
  (text: string) => {
    const [_salt, _nonce = '', _cipher = '', ...aad] = text.split(SPLITTER);
    const salt = decodeBase64(_salt);
    const nonce = decodeBase64(_nonce);
    const cipher = decodeBase64(_cipher);
    return {
      salt,
      nonce,
      cipher,
      aad: aad.length ? aad.join(SPLITTER) : undefined,
    };
  },
];

const AES_GCM = 'AES-GCM';
const AES_GCM_KEY_LENGTH = 32;
const SALT_LENGTH = 32;
const NONCE_LENGTH = 16;
const PBKDF2 = 'PBKDF2';
const PBKDF2_ITERATIONS = 1e6;
const HKDF = 'HKDF';
const HKDF_INFO = new Uint8Array();
const HASH = 'SHA-512';

const App = () => {
  const [wait, setWait] = useState(false);
  const [focus, setFocus] = useState(false);
  const [sync, setSync] = useState(false);

  const [key, setKey] = useState('');

  const [plaintext, setPlaintext] = useState('');
  const [ciphertext, setCiphertext] = useState('');

  const [aad, setAAD] = useState('');

  const [shared, setShared] = useState(false);

  const [wasm, setWasm] = useState(false);

  const [chacha, setChacha] = useState(true);

  const wasmed = useMemo(() => wasm && shared, [shared, wasm]);

  const KDF = useMemo(() => (shared ? HKDF : PBKDF2), [shared]);

  const encrypt = useCallback(async () => {
    setWait(true);
    try {
      const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
      const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
      const text = wasmed
        ? await pont$$encrypt(
            chacha ? 'ChaCha20-Poly1305' : 'AES-256-GCM',
            key,
            plaintext,
            aad
          )
        : wrapCipher(
            salt,
            nonce,
            new Uint8Array(
              await crypto.subtle.encrypt(
                {
                  name: AES_GCM,
                  iv: nonce,
                  ...(aad ? { additionalData: encodeText(aad) } : undefined),
                },
                await crypto.subtle.deriveKey(
                  KDF === HKDF
                    ? { name: HKDF, hash: HASH, info: HKDF_INFO, salt }
                    : {
                        name: PBKDF2,
                        hash: HASH,
                        iterations: PBKDF2_ITERATIONS,
                        salt,
                      },
                  await crypto.subtle.importKey(
                    'raw',
                    KDF === HKDF ? encodeRaw(key) : encodeText(key),
                    KDF,
                    false,
                    ['deriveKey']
                  ),
                  { name: AES_GCM, length: AES_GCM_KEY_LENGTH * 8 },
                  false,
                  ['encrypt']
                ),
                encodeText(plaintext)
              )
            ),
            aad
          );
      setCiphertext(text);
      setSync(true);
      await copy(text);
    } catch (e) {
      console.error(e);
      alert(e);
    } finally {
      setWait(false);
    }
  }, [wasmed, chacha, key, plaintext, aad, KDF]);

  const decrypt = useCallback(async () => {
    setWait(true);
    try {
      if (wasmed) {
        const { suite, plaintext, aad } = await pont$$decrypt(key, ciphertext);
        setChacha(suite === 'ChaCha20-Poly1305');
        setPlaintext(plaintext);
        setAAD(aad);
      } else {
        const { salt, nonce, cipher, aad } = unwrapCipher(ciphertext);
        setPlaintext(
          decodeText(
            await crypto.subtle.decrypt(
              {
                name: AES_GCM,
                iv: nonce,
                ...(aad ? { additionalData: encodeText(aad) } : undefined),
              },
              await crypto.subtle.deriveKey(
                KDF === HKDF
                  ? { name: HKDF, hash: HASH, info: HKDF_INFO, salt }
                  : {
                      name: PBKDF2,
                      hash: HASH,
                      iterations: PBKDF2_ITERATIONS,
                      salt,
                    },
                await crypto.subtle.importKey(
                  'raw',
                  KDF === HKDF ? encodeRaw(key) : encodeText(key),
                  KDF,
                  false,
                  ['deriveKey']
                ),
                { name: AES_GCM, length: AES_GCM_KEY_LENGTH * 8 },
                false,
                ['decrypt']
              ),
              cipher
            )
          )
        );
        setAAD(aad ?? '');
      }
      setSync(true);
    } catch (e) {
      console.error(e);
      alert(e);
    } finally {
      setWait(false);
    }
  }, [wasmed, key, ciphertext, KDF]);

  const handleFocus = useCallback(async () => {
    try {
      const text = await paste();
      if (text) {
        const { salt, nonce, cipher } = unwrapCipher(text);
        if (salt.length && nonce.length && cipher.length) setCiphertext(text);
      }
    } catch {}
  }, []);

  const icon = useMemo(
    () => (sync ? (shared ? '🔐' : '🔒') : shared ? '🔑' : '🔓'),
    [shared, sync]
  );

  const style = useMemo(
    () =>
      ({
        color:
          sync && shared
            ? 'teal'
            : sync
            ? 'green'
            : shared
            ? 'blue'
            : undefined,
      } as CSSProperties),
    [shared, sync]
  );

  useEffect(() => {
    (async () => {
      const go = new Go();
      const { instance } = await WebAssembly.instantiateStreaming(
        Promise.race([
          fetch('pont.wasm'),
          fetch(
            'https://cdn.jsdelivr.net/gh/jamesliu96/pont@gh-pages/pont.wasm'
          ).catch(() => new Promise<Response>(() => {})),
        ]),
        go.importObject
      );
      await go.run(instance);
    })();
    const handleMessage = ({
      data,
    }: MessageEvent<{ bin?: unknown; $$?: unknown } | undefined>) => {
      if (typeof data?.bin === 'string' && data.bin) {
        setKey(data.bin);
        setShared(true);
        setSync(false);
      }
      if (data?.$$) {
        setWasm(true);
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
            placeholder="key"
            type={shared ? 'password' : focus ? 'text' : 'password'}
            value={key}
            style={style}
            onChange={(e) => {
              setKey(e.target.value);
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
            rows={4}
            disabled={wait}
            placeholder="plaintext"
            value={plaintext}
            style={style}
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
            style={style}
            onChange={(e) => {
              setAAD(e.target.value);
              setSync(false);
            }}
          />
        </section>
        {wasmed ? (
          <>
            <section
              style={{ textWrap: 'nowrap', fontSize: 'x-small', width: 'auto' }}
            >
              <input
                type="radio"
                id="chacha"
                checked={chacha}
                style={{ margin: 0 }}
                onChange={() => {
                  setChacha(true);
                  setSync(false);
                }}
              />
              <label htmlFor="chacha" style={style}>
                ChaCha20-Poly1305
              </label>
            </section>
            <section
              style={{ textWrap: 'nowrap', fontSize: 'x-small', width: 'auto' }}
            >
              <input
                type="radio"
                id="aes"
                checked={!chacha}
                style={{ margin: 0 }}
                onChange={() => {
                  setChacha(false);
                  setSync(false);
                }}
              />
              <label htmlFor="aes" style={style}>
                AES-256-GCM
              </label>
            </section>
          </>
        ) : null}
        <section>
          <button disabled={wait} style={style} onClick={encrypt}>
            Encrypt
          </button>
          <div
            style={{ cursor: wait ? undefined : 'pointer' }}
            onContextMenu={(e) => {
              if (wait) return;
              e.preventDefault();
              setShared(false);
              setSync(false);
            }}
          >
            {icon}
          </div>
          <button disabled={wait} style={style} onClick={decrypt}>
            Decrypt
          </button>
        </section>
        <section>
          <textarea
            rows={8}
            disabled={wait}
            spellCheck={false}
            placeholder="ciphertext"
            value={ciphertext}
            style={style}
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
          <a
            href="https://geheim.jamesliu.info"
            target="_blank"
            rel="noreferrer"
          >
            geheim
          </a>
        </div>
        {wasmed ? (
          <>
            <div>+</div>
            <div>
              <a
                href="https://github.com/jamesliu96/ego"
                target="_blank"
                rel="noreferrer"
              >
                ego
              </a>
            </div>
          </>
        ) : (
          <>
            <div>and</div>
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
          </>
        )}
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

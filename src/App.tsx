import {
  CSSProperties,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react';

import './App.css';

import './wasm_exec.js';

// const [encodeRaw, decodeRaw] = [
//   (str: string) => Uint8Array.from(str, (v) => v.charCodeAt(0)),
//   (bin: Uint8Array) => String.fromCharCode(...bin),
// ];

const [TE, TD] = [new TextEncoder(), new TextDecoder()];
const [encodeText, decodeText] = [
  (str: string) => TE.encode(str),
  (bin: BufferSource) => TD.decode(bin),
];

const [encodeBase64, decodeBase64] = [
  (bin: Uint8Array) => btoa(String.fromCodePoint(...bin)).replace(/=+$/g, ''),
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

const [wrapCipher, unwrapCipher, splitCipher] = [
  (
    salt: Uint8Array,
    nonce: Uint8Array,
    text: Uint8Array,
    aad: string | undefined,
    splitter = '|'
  ) =>
    [
      encodeBase64(salt),
      encodeBase64(nonce),
      encodeBase64(text),
      ...(aad ? [aad] : []),
    ].join(splitter),
  (text: string, splitter = '|') => {
    const {
      salt: _salt,
      nonce: _nonce,
      cipher: _cipher,
      aad,
    } = splitCipher(text, splitter);
    const salt = decodeBase64(_salt);
    const nonce = decodeBase64(_nonce);
    const cipher = decodeBase64(_cipher);
    return {
      salt,
      nonce,
      cipher,
      aad,
    };
  },
  (text: string, splitter = '|') => {
    const [salt, nonce = '', cipher = '', ...aad] = text.split(splitter);
    return {
      salt,
      nonce,
      cipher,
      aad: aad.length ? aad.join(splitter) : undefined,
    };
  },
];

const AES_GCM = 'AES-GCM';
const AES_GCM_KEY_LENGTH = 32;
const SALT_LENGTH = 32;
const NONCE_LENGTH = 16;
const PBKDF2 = 'PBKDF2';
const PBKDF2_ITERATIONS = 1e6;
const HASH = 'SHA-256';

const App = () => {
  const [wait, setWait] = useState(false);
  const [focus, setFocus] = useState(false);
  const [sync, setSync] = useState(false);

  const [key, setKey] = useState('');

  const [plaintext, setPlaintext] = useState('');
  const [ciphertext, setCiphertext] = useState('');
  const [aad, setAAD] = useState('');

  const [shared, setShared] = useState(false);
  const [modes, setModes] = useState<string[]>();
  const [mode, setMode] = useState<string>();

  const encrypt = useCallback(async () => {
    setWait(true);
    try {
      const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
      const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
      const text =
        mode && shared
          ? await pont$$encrypt(mode, key, plaintext, aad)
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
                    {
                      name: PBKDF2,
                      hash: HASH,
                      iterations: PBKDF2_ITERATIONS,
                      salt,
                    },
                    await crypto.subtle.importKey(
                      'raw',
                      encodeText(key),
                      PBKDF2,
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
  }, [shared, mode, key, plaintext, aad]);

  const decrypt = useCallback(async () => {
    setWait(true);
    try {
      if (mode && shared) {
        const { suite, plaintext, aad } = await pont$$decrypt(key, ciphertext);
        setMode(suite);
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
                {
                  name: PBKDF2,
                  hash: HASH,
                  iterations: PBKDF2_ITERATIONS,
                  salt,
                },
                await crypto.subtle.importKey(
                  'raw',
                  encodeText(key),
                  PBKDF2,
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
  }, [mode, shared, key, ciphertext]);

  const handleFocus = useCallback(async () => {
    try {
      const text = await paste();
      if (text) {
        let { salt, nonce, cipher } = splitCipher(text);
        if (salt.length && nonce.length && cipher.length) {
          setCiphertext((ciphertext) => {
            if (ciphertext !== text) setSync(false);
            return text;
          });
          return;
        }
        ({ salt, nonce, cipher } = splitCipher(text, '#'));
        if (salt.length && nonce.length && cipher.length) {
          setCiphertext((ciphertext) => {
            if (ciphertext !== text) setSync(false);
            return text;
          });
          return;
        }
        ({ salt, nonce, cipher } = splitCipher(text, '$'));
        if (salt.length && nonce.length && cipher.length) {
          setCiphertext((ciphertext) => {
            if (ciphertext !== text) setSync(false);
            return text;
          });
          return;
        }
        ({ salt, nonce, cipher } = splitCipher(text, ':'));
        if (salt.length && nonce.length && cipher.length) {
          setCiphertext((ciphertext) => {
            if (ciphertext !== text) setSync(false);
            return text;
          });
          return;
        }
        ({ salt, nonce, cipher } = splitCipher(text, '@'));
        if (salt.length && nonce.length && cipher.length) {
          setCiphertext((ciphertext) => {
            if (ciphertext !== text) setSync(false);
            return text;
          });
          return;
        }
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
        color: sync ? 'green' : shared ? 'blue' : undefined,
      } as CSSProperties),
    [shared, sync]
  );

  useEffect(() => {
    (async () => {
      const go = new Go();
      const source = await WebAssembly.instantiateStreaming(
        process.env.NODE_ENV === 'development'
          ? fetch('pts.wasm')
          : Promise.race([
              fetch('pts.wasm'),
              fetch(
                'https://cdn.jsdelivr.net/gh/jamesliu96/pont@gh-pages/pts.wasm'
              ).catch(() => new Promise<Response>(() => {})),
            ]),
        go.importObject
      );
      const { module } = source;
      for (;;) {
        let { instance } = source;
        await go.run(instance);
        instance = await WebAssembly.instantiate(module, go.importObject);
      }
    })();
    const handleMessage = ({
      data,
    }: MessageEvent<{ bin: unknown; $$: unknown } | undefined>) => {
      if (typeof data?.bin === 'string') {
        setKey((key) => {
          if (typeof data?.bin !== 'string') return key;
          if (key !== data.bin) setSync(false);
          return data.bin;
        });
        setShared(true);
      }
      if (Array.isArray(data?.$$) && data?.$$.length) {
        setModes(data.$$);
        setMode(data.$$[0]);
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
            type={focus ? 'text' : 'password'}
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
        <section>
          {modes?.length && shared ? (
            <select
              disabled={wait}
              value={mode}
              style={{ ...style, width: '100%', fontSize: 'small' }}
              onChange={(e) => {
                setMode(e.target.value);
                setSync(false);
              }}
            >
              {modes.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          ) : null}
        </section>
        <section>
          <button
            disabled={wait || (!modes?.length && shared) || !key}
            style={style}
            onClick={encrypt}
          >
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
          <button
            disabled={wait || (!modes?.length && shared) || !key}
            style={style}
            onClick={decrypt}
          >
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
        {modes?.length && shared ? (
          <>
            <div style={{ lineHeight: 1 }}>+</div>
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

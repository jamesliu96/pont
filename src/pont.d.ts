type Suite = 'AES-256-GCM_SHA256' | 'ChaCha20-Poly1305_SHA256';

declare function pont$$encrypt(
  suite: Suite,
  key: string,
  plaintext: string,
  aad: string
): Promise<string>;

declare function pont$$decrypt(
  key: string,
  ciphertext: string
): Promise<{ suite: Suite; plaintext: string; aad: string }>;

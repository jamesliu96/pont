type Suite = 'AES-256-GCM' | 'ChaCha20-Poly1305';

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

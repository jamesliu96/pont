declare function pont$$encrypt(
  suite: string,
  key: string,
  plaintext: string,
  aad: string
): Promise<string>;

declare function pont$$decrypt(
  key: string,
  ciphertext: string
): Promise<{ suite: string; plaintext: string; aad: string }>;

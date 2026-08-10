import { x25519 } from "@noble/curves/ed25519";
import { toBase64 } from "./bytes";

export interface WireGuardKeys {
  priv: string;
  pub: string;
}

/**
 * WireGuard keypair (Curve25519). The private key is 32 random bytes stored
 * base64; the public key is scalar-mult-base of it (clamped per RFC 7748 inside
 * getPublicKey — the same clamp `wg` applies when it loads the private key, so
 * the pair stays consistent). This matches how the Node build used
 * crypto x25519 and how the reference generator uses tweetnacl box keys.
 */
export function generateWireGuardKeys(): WireGuardKeys {
  const priv = x25519.utils.randomPrivateKey();
  const pub = x25519.getPublicKey(priv);
  return { priv: toBase64(priv), pub: toBase64(pub) };
}

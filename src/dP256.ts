/**
 *
 * Copyright 2024 Algorand Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

import { p256 } from '@noble/curves/nist';
import { validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

/**
 * DeterministicP256 - a class that generates deterministic P-256 keypairs from a BIP39 phrase and a
 * domain-specific origin and userHandle.
 *
 * For generating passkeys intended for FIDO2-based authentication to web services, in a
 * deterministic manner that allows a user to regenerate the same keypair on different devices.
 *
 * 1) Start by generating a derived main key from a BIP39 phrase using PBKDF2-HMAC-SHA512 with 210k
 * iterations. This should only be run once per device, and the derived main key should be stored
 * securely. The mnemonic phrase should only be inputed once and then be discarded by the device.
 *
 * 2) Generate a domain-specific keypair from the derived main key, origin, and userHandle. The
 * origin is the domain of the service, and the userHandle is the user's unique identifier on that
 * service. A counter can also be set in case it is pertinent to generate multiple passkeys for a
 * service.
 *
 * 3) Sign a payload with the domain-specific keypair. The keypairs can be stored and retreived from
 * storage using some secure storage mechanism.
 */
export class DeterministicP256 {
  /**
   * Generates a derived main key using a BIP39 mnemonic phrase.
   *
   * This function validates the provided BIP39 mnemonic phrase and then derives a main key using the specified parameters.
   * The derived key is generated using the PBKDF2 key derivation function with HMAC-SHA512.
   *
   * @param phrase - A BIP39 mnemonic phrase used as the entropy source for key derivation.
   * @param salt - An optional salt value used in the key derivation process. Defaults to the UTF-8 encoded string "liquid".
   * @param iterationCount - The number of iterations to perform in the key derivation process. Defaults to 210,000.
   * @param keyLength - The desired length of the derived key in bits. Defaults to 512 bits.
   *
   * @returns A `Uint8Array` containing the derived key.
   *
   * @throws An error if the mnemonic phrase is invalid or if the key derivation process fails.
   *
   * @note The `keyLength` parameter is integer divided by 8 internally to convert the length from bits to full bytes.
   */
  public genDerivedMainKeyWithBIP39(
    phrase: string,
    salt: Uint8Array = new TextEncoder().encode('liquid'),
    iterationCount: number = 210_000,
    keyLength: number = 512
  ): Promise<Uint8Array> {
    // Validate the key length
    if (keyLength % 8 !== 0) {
      throw new Error('Key length must be divisible by 8.');
    }

    // Validate the mnemonic phrase
    if (!validateMnemonic(phrase, wordlist)) {
      throw new Error('Invalid mnemonic phrase.');
    }

    return this.genDerivedMainKey(
      new TextEncoder().encode(phrase),
      salt,
      iterationCount,
      keyLength / 8
    );
  }

  /**
   * Generates a derived key using the PBKDF2 key derivation function with HMAC-SHA512.
   *
   * This function derives a key from the provided entropy and salt using the specified iteration count and key length.
   * The derived key is generated using the PBKDF2 key derivation function with HMAC-SHA512.
   *
   * @param entropy - A Uint8Array representing the entropy source for key derivation.
   * @param salt - A Uint8Array representing the salt value used in the key derivation process.
   * @param iterationCount - The number of iterations to perform in the key derivation process.
   * @param keyLengthBytes - The desired length of the derived key in bytes.
   *
   * @returns A Promise resolving to a `Uint8Array` containing the derived key.
   *
   * @throws An error if the key derivation process fails.
   *
   * @note The `keyLengthBytes` parameter specifies the length of the derived key in bytes.
   */
  public async genDerivedMainKey(
    entropy: Uint8Array,
    salt: Uint8Array,
    iterationCount: number,
    keyLengthBytes: number
  ): Promise<Uint8Array> {
    // Convert Uint8Array to proper ArrayBuffer for Web Crypto API
    const entropyBuffer = new Uint8Array(entropy).buffer;
    const saltBuffer = new Uint8Array(salt).buffer;

    const key = await crypto.subtle.importKey(
      'raw',
      entropyBuffer,
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: saltBuffer,
        iterations: iterationCount,
        hash: 'SHA-512'
      },
      key,
      keyLengthBytes * 8
    );

    return new Uint8Array(derivedBits);
  }

  /**
   * Generates a domain-specific key pair using a derived main key, origin, user ID, and an optional counter.
   *
   * This function concatenates the provided derived main key, origin, user ID, and counter to create a unique input.
   * It then calculates the SHA-512 hash of this input and uses the first 32 bytes of the hash as the seed to
   * generate a P256 private key. The origin and userHandle are meant to correspond to their WebAuthn counterparts
   * but they can be any strings that help to uniquely identify the key pair.
   *
   * @param derivedMainKey - A `Uint8Array` representing the derived main key.
   * @param origin - A `string` representing the origin or domain for which the key pair is being generated.
   * @param userHandle - A `string` representing the user ID.
   * @param counter - An optional `number` counter to ensure uniqueness. Defaults to 0.
   *
   * @returns A `Uint8Array` representing the generated private key.
   *
   * @throws An error if the key generation fails.
   *
   * @note The SHA-512 hash is calculated using the Web Crypto API, and only the first 32 bytes of the hash
   * are used as the seed for the private key, similar to BC in the Kotlin implementation. Certain java.security providers
   * accept 40 bytes of seed but we explicitly ensure it is 32 bytes.
   */
  public async genDomainSpecificKeyPair(
    derivedMainKey: Uint8Array,
    origin: string,
    userHandle: string,
    counter: number = 0
  ): Promise<Uint8Array> {
    // Create concatenated input
    const originBytes = new TextEncoder().encode(origin);
    const userHandleBytes = new TextEncoder().encode(userHandle);

    // Convert counter to big-endian 4-byte representation
    const counterBuffer = new ArrayBuffer(4);
    new DataView(counterBuffer).setUint32(0, counter, false); // false = big-endian
    const counterBytes = new Uint8Array(counterBuffer);

    // Concatenate all inputs
    const totalLength = derivedMainKey.length + originBytes.length + userHandleBytes.length + counterBytes.length;
    const concat = new Uint8Array(totalLength);
    let offset = 0;

    concat.set(derivedMainKey, offset);
    offset += derivedMainKey.length;

    concat.set(originBytes, offset);
    offset += originBytes.length;

    concat.set(userHandleBytes, offset);
    offset += userHandleBytes.length;

    concat.set(counterBytes, offset);

    // Calculate SHA-512 hash
    const hashBuffer = await crypto.subtle.digest('SHA-512', concat);
    const hash = new Uint8Array(hashBuffer);

    // Use first 32 bytes as seed for private key
    const seed = hash.slice(0, 32);

    // Ensure the seed is a valid private key for P256
    // If the seed is >= curve order, we need to reduce it
    if (this.isValidPrivateKey(seed)) {
      return seed;
    } else {
      // Fallback: hash the seed again if it's not valid
      const fallbackHashBuffer = await crypto.subtle.digest('SHA-256', seed);
      const fallbackSeed = new Uint8Array(fallbackHashBuffer);

      if (this.isValidPrivateKey(fallbackSeed)) {
        return fallbackSeed;
      } else {
        throw new Error('Failed to generate valid private key');
      }
    }
  }

  /**
   * Signs a payload using a domain-specific private key.
   *
   * This function takes a P256 private key and a payload, and generates an ECDSA signature for the
   * payload using the private key.
   *
   * @param privateKey - A `Uint8Array` representing the domain-specific private key.
   * @param payload - A `Uint8Array` representing the payload to be signed.
   *
   * @returns A `Uint8Array` representing the generated signature in compact format.
   *
   * @throws An error if the signing process fails.
   *
   * @note The signature is generated using the ECDSA algorithm with the P256 curve.
   */
  public signWithDomainSpecificKeyPair(privateKey: Uint8Array, payload: Uint8Array): Uint8Array {
    const signature = p256.sign(payload, privateKey);
    return signature.toCompactRawBytes();
  }

  /**
   * Retrieves the raw public key bytes from a P256 private key.
   *
   * This method provides API parity with the Kotlin and Swift implementations.
   *
   * In the current TypeScript implementation using @noble/curves, the public key is simple to retrieve
   * in raw representation. This method returns the exact same bytes as the equivalent `getPurePKBytes`
   * methods in the Kotlin and Swift implementations.
   *
   * @param privateKey - A `Uint8Array` representing the private key from which to extract the public key bytes.
   *
   * @returns A `Uint8Array` containing the raw public key bytes.
   */
  public getPurePKBytes(privateKey: Uint8Array): Uint8Array {
    // Get uncompressed public key (65 bytes: 0x04 + 32 bytes X + 32 bytes Y)
    const publicKey = p256.getPublicKey(privateKey, false);
    // Return the 64 bytes (X + Y coordinates) without the 0x04 prefix
    return publicKey.slice(1);
  }

  /**
   * Validates if a byte array represents a valid P256 private key.
   * A valid private key must be in the range [1, n-1] where n is the curve order.
   *
   * @param key - The potential private key bytes
   * @returns true if the key is valid, false otherwise
   */
  private isValidPrivateKey(key: Uint8Array): boolean {
    // Convert to bigint for comparison
    let keyValue = 0n;
    for (let i = 0; i < key.length; i++) {
      keyValue = (keyValue << 8n) + BigInt(key[i]);
    }

    // P256 curve order (n)
    const curveOrder = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

    // Key must be in range [1, n-1]
    return keyValue > 0n && keyValue < curveOrder;
  }

  /**
   * Converts a raw ECDSA signature (64 bytes: 32 bytes r + 32 bytes s) to DER format.
   * 
   * @param rawSignature - 64-byte raw signature (32 bytes r + 32 bytes s)
   * @returns DER-encoded signature
   */
  public rawToDER(rawSignature: Uint8Array): Uint8Array {
    if (rawSignature.length !== 64) {
      throw new Error('Raw signature must be exactly 64 bytes');
    }

    const r = rawSignature.slice(0, 32);
    const s = rawSignature.slice(32, 64);

    // Convert to DER format
    const rDER = this.encodeDERInteger(r);
    const sDER = this.encodeDERInteger(s);

    // Build SEQUENCE
    const content = new Uint8Array(rDER.length + sDER.length);
    content.set(rDER, 0);
    content.set(sDER, rDER.length);

    // DER SEQUENCE tag (0x30) + length + content
    return this.encodeDERSequence(content);
  }

  /**
   * Converts a DER-encoded ECDSA signature to raw format (64 bytes: 32 bytes r + 32 bytes s).
   * 
   * @param derSignature - DER-encoded signature
   * @returns 64-byte raw signature (32 bytes r + 32 bytes s)
   */
  public derToRaw(derSignature: Uint8Array): Uint8Array {
    if (derSignature[0] !== 0x30) {
      throw new Error('Invalid DER signature: must start with SEQUENCE tag (0x30)');
    }

    let offset = 1;
    const sequenceLength = this.decodeDERLength(derSignature, offset);
    offset += this.getDERLengthSize(derSignature[offset]);

    // Parse r
    if (derSignature[offset] !== 0x02) {
      throw new Error('Invalid DER signature: expected INTEGER tag (0x02) for r');
    }
    offset++;
    const rLength = this.decodeDERLength(derSignature, offset);
    offset += this.getDERLengthSize(derSignature[offset]);
    const rBytes = derSignature.slice(offset, offset + rLength);
    offset += rLength;

    // Parse s
    if (derSignature[offset] !== 0x02) {
      throw new Error('Invalid DER signature: expected INTEGER tag (0x02) for s');
    }
    offset++;
    const sLength = this.decodeDERLength(derSignature, offset);
    offset += this.getDERLengthSize(derSignature[offset]);
    const sBytes = derSignature.slice(offset, offset + sLength);

    // Convert to 32-byte arrays (pad with zeros if needed, remove leading zeros if present)
    const r = this.padTo32Bytes(rBytes);
    const s = this.padTo32Bytes(sBytes);

    // Combine r and s
    const result = new Uint8Array(64);
    result.set(r, 0);
    result.set(s, 32);

    return result;
  }

  private encodeDERInteger(bytes: Uint8Array): Uint8Array {
    // Remove leading zeros
    let start = 0;
    while (start < bytes.length && bytes[start] === 0) {
      start++;
    }

    // If all bytes were zero, keep one zero
    if (start === bytes.length) {
      start = bytes.length - 1;
    }

    let content = bytes.slice(start);

    // If the first bit is set, prepend a zero byte to indicate positive integer
    if (content[0] & 0x80) {
      const padded = new Uint8Array(content.length + 1);
      padded[0] = 0x00;
      padded.set(content, 1);
      content = padded;
    }

    // INTEGER tag (0x02) + length + content
    const result = new Uint8Array(2 + content.length);
    result[0] = 0x02; // INTEGER tag
    result[1] = content.length; // length
    result.set(content, 2);

    return result;
  }

  private encodeDERSequence(content: Uint8Array): Uint8Array {
    const result = new Uint8Array(2 + content.length);
    result[0] = 0x30; // SEQUENCE tag
    result[1] = content.length; // length
    result.set(content, 2);
    return result;
  }

  private decodeDERLength(data: Uint8Array, offset: number): number {
    const firstByte = data[offset];
    if (firstByte & 0x80) {
      throw new Error('Long form DER length encoding not supported in this implementation');
    }
    return firstByte;
  }

  private getDERLengthSize(lengthByte: number): number {
    return 1; // We only support short form (length < 128)
  }

  private padTo32Bytes(bytes: Uint8Array): Uint8Array {
    if (bytes.length === 32) {
      return bytes;
    } else if (bytes.length < 32) {
      // Pad with leading zeros
      const result = new Uint8Array(32);
      result.set(bytes, 32 - bytes.length);
      return result;
    } else {
      // Remove leading zeros (should not happen in well-formed signatures)
      let start = 0;
      while (start < bytes.length - 32 && bytes[start] === 0) {
        start++;
      }
      return bytes.slice(start, start + 32);
    }
  }
}
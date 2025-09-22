# Deterministic P256 TypeScript

A TypeScript implementation for generating deterministic P-256 keypairs from BIP39 mnemonic phrases. This library enables the creation of reproducible cryptographic keypairs for WebAuthn/FIDO2 authentication across different devices.

## Features

- 🔐 Generate deterministic P-256 keypairs from BIP39 mnemonic phrases
- 🌐 Domain-specific key generation for WebAuthn/FIDO2 use cases
- 🔄 Cross-platform compatibility (equivalent to Swift and Kotlin implementations)
- 🧪 Comprehensive test coverage
- 📦 Modern TypeScript with full type support

## Installation

```bash
npm install dp256-ts
```

## Usage

### Basic Example

```typescript
import { DeterministicP256 } from 'dp256-ts';

const dp256 = new DeterministicP256();

// Step 1: Generate derived main key from BIP39 phrase
const phrase =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const derivedKey = await dp256.genDerivedMainKeyWithBIP39(phrase);

// Step 2: Generate domain-specific keypair
const privateKey = await dp256.genDomainSpecificKeyPair(
  derivedKey,
  'webauthn.example.com', // origin/domain
  'alice@example.com' // user handle
);

// Step 3: Get public key bytes
const publicKeyBytes = dp256.getPurePKBytes(privateKey);

// Step 4: Sign a payload
const payload = new TextEncoder().encode('authenticate user alice');
const signature = dp256.signWithDomainSpecificKeyPair(privateKey, payload);

console.log('Private key length:', privateKey.length); // 32 bytes
console.log('Public key length:', publicKeyBytes.length); // 64 bytes (X + Y coordinates)
console.log('Signature length:', signature.length); // 64 bytes
```

### Advanced Configuration

```typescript
// Custom salt and iteration count
const customDerivedKey = await dp256.genDerivedMainKeyWithBIP39(
  phrase,
  new TextEncoder().encode('custom-salt'), // custom salt
  100_000, // iteration count
  512 // key length in bits
);

// Multiple keypairs for same domain using counter
const keypair1 = await dp256.genDomainSpecificKeyPair(derivedKey, 'example.com', 'user', 0);
const keypair2 = await dp256.genDomainSpecificKeyPair(derivedKey, 'example.com', 'user', 1);
```

## API Reference

### `genDerivedMainKeyWithBIP39(phrase, salt?, iterationCount?, keyLength?)`

Generates a derived main key from a BIP39 mnemonic phrase using PBKDF2-HMAC-SHA512.

- **phrase**: BIP39 mnemonic phrase
- **salt**: Salt for key derivation (default: `"liquid"`)
- **iterationCount**: PBKDF2 iterations (default: `210_000`)
- **keyLength**: Key length in bits (default: `512`)

Returns: `Promise<Uint8Array>`

### `genDomainSpecificKeyPair(derivedMainKey, origin, userHandle, counter?)`

Generates a domain-specific P-256 private key.

- **derivedMainKey**: Output from `genDerivedMainKeyWithBIP39`
- **origin**: Domain/origin identifier
- **userHandle**: User identifier
- **counter**: Optional counter for multiple keys (default: `0`)

Returns: `Promise<Uint8Array>`

### `signWithDomainSpecificKeyPair(privateKey, payload)`

Signs a payload using the private key.

- **privateKey**: Private key from `genDomainSpecificKeyPair`
- **payload**: Data to sign

Returns: `Uint8Array` (64-byte signature)

### `getPurePKBytes(privateKey)`

Extracts the raw public key bytes from a private key.

- **privateKey**: Private key from `genDomainSpecificKeyPair`

Returns: `Uint8Array` (64-byte uncompressed public key coordinates)

## Security Considerations

- The BIP39 mnemonic phrase should be generated with sufficient entropy
- Store the derived main key securely and never expose the original mnemonic
- This library is designed for deterministic key generation across devices
- The PBKDF2 iteration count provides additional security hardening

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Run tests in watch mode
npm run test:watch
```

## License

Apache-2.0

## Compatibility

This implementation is equivalent to the Swift and Kotlin versions and produces identical keypairs for the same inputs across all platforms.

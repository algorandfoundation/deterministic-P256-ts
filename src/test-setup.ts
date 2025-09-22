// Test setup to make Web Crypto API available in Node.js Jest environment
import { webcrypto } from 'node:crypto';

// Make Web Crypto API available globally in tests
Object.defineProperty(globalThis, 'crypto', {
  value: webcrypto,
});

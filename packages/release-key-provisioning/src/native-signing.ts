/**
 * Historical v1 helper inspection surface. The returned adapter deliberately
 * hard-refuses add, key-matching verification, and signing until a v2 stable
 * signed component supplies enforceable caller identity and Keychain access.
 */
export {
  createNativeKeychainAdapter,
  readPlatformIdentitySha256,
  type DisposableKeychainAdapter as NativeFoundationKeychainAdapter,
} from "./host.js";

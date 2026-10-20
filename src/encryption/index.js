// Copyright 2026 Tether Operations Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
'use strict'

import { gcm } from '@noble/ciphers/aes.js'
import { clean, bytesToHex, bytesToUtf8, hexToBytes, randomBytes, utf8ToBytes } from '@noble/ciphers/utils.js'
import { scrypt } from '@noble/hashes/scrypt.js'

/**
 * @typedef {Object} ScryptParams
 * @property {number} [N] - scrypt CPU/memory cost parameter (power of 2).
 * @property {number} [r] - scrypt block size parameter.
 * @property {number} [p] - scrypt parallelization parameter.
 */

/**
 * @typedef {Object} EncryptedPayload
 * @property {1} version - The payload format version.
 * @property {string} salt - The scrypt salt (hex).
 * @property {string} iv - The AES-GCM initialization vector (hex).
 * @property {string} tag - The AES-GCM authentication tag (hex).
 * @property {string} ciphertext - The encrypted payload (hex).
 * @property {number} [scryptN] - scrypt N used for key derivation.
 * @property {number} [scryptR] - scrypt r used for key derivation.
 * @property {number} [scryptP] - scrypt p used for key derivation.
 */

const KEY_LEN = 32
const SALT_LEN = 32
const IV_LEN = 12
const GCM_TAG_LEN = 16
const SCRYPT_MAX_MEM = 256 * 1024 * 1024
const SCRYPT_MAX_R = 32
const SCRYPT_MAX_P = 4

/**
 * `randomBytes()` (via @noble/ciphers) reads `crypto.getRandomValues` off
 * `globalThis`. React Native's Hermes engine doesn't provide it, which
 * surfaces there as an opaque "crypto.getRandomValues must be defined"
 * throw with no indication of the fix. We check and return an actionable error.
 */
function assertSecureRandomAvailable () {
  if (typeof globalThis.crypto?.getRandomValues !== 'function') {
    throw new Error(
      'crypto.getRandomValues is not available in this environment. ' +
      'On React Native, install `react-native-get-random-values` and import it ' +
      'as the first import in your app entry point, before anything that imports ' +
      '@tetherto/wdk-utils. See the README "Platform Requirements" section.'
    )
  }
}

/** @type {Required<ScryptParams>} */
export const DEFAULT_SCRYPT_PARAMS = {
  N: 2 ** 16,
  r: 8,
  p: 1
}

/**
 * @param {ScryptParams | EncryptedPayload} [params]
 * @returns {Required<ScryptParams>}
 */
function resolveScryptParams (params = {}) {
  return {
    N: params.N ?? params.scryptN ?? DEFAULT_SCRYPT_PARAMS.N,
    r: params.r ?? params.scryptR ?? DEFAULT_SCRYPT_PARAMS.r,
    p: params.p ?? params.scryptP ?? DEFAULT_SCRYPT_PARAMS.p
  }
}

/**
 * @param {Required<ScryptParams>} scryptParams
 * @throws {Error} If r, p or the memory needed by N and r exceed the supported limits.
 */
function assertSupportedScryptParams ({ N, r, p }) {
  if (r > SCRYPT_MAX_R || p > SCRYPT_MAX_P || 128 * r * N > SCRYPT_MAX_MEM) {
    throw new Error(`Unsupported scrypt parameters: r must not exceed ${SCRYPT_MAX_R}, p must not exceed ${SCRYPT_MAX_P} and 128 * r * N must not exceed ${SCRYPT_MAX_MEM} bytes`)
  }
}

/**
 * Derives a 32-byte encryption key from a password and salt using scrypt.
 *
 * @param {string} password - The passphrase.
 * @param {Uint8Array} salt - The salt bytes.
 * @param {ScryptParams} [scryptParams] - Optional scrypt cost parameters.
 * @returns {Uint8Array} The derived key bytes.
 * @throws {Error} If the scrypt parameters are invalid, or exceed the supported limits (r <= 32, p <= 4, 128 * r * N <= 256 MiB).
 */
export function deriveKey (password, salt, scryptParams) {
  const resolved = resolveScryptParams(scryptParams)
  assertSupportedScryptParams(resolved)
  return scrypt(password, salt, {
    N: resolved.N,
    r: resolved.r,
    p: resolved.p,
    dkLen: KEY_LEN,
    maxmem: SCRYPT_MAX_MEM + 128 * resolved.r * (resolved.p + 1)
  })
}

/**
 * Encrypts a plaintext string with AES-256-GCM using a password-derived key.
 *
 * @param {string} plaintext - The string to encrypt.
 * @param {string} password - The passphrase used to derive the key.
 * @param {ScryptParams} [scryptParams] - Optional scrypt cost parameters.
 * @returns {EncryptedPayload} The encrypted payload including salt, IV, tag, and ciphertext.
 * @throws {Error} If the scrypt parameters are invalid, or exceed the supported limits (r <= 32, p <= 4, 128 * r * N <= 256 MiB).
 */
export function encrypt (plaintext, password, scryptParams) {
  assertSecureRandomAvailable()
  const resolved = resolveScryptParams(scryptParams)
  const salt = randomBytes(SALT_LEN)
  const key = deriveKey(password, salt, resolved)
  const iv = randomBytes(IV_LEN)

  try {
    const sealed = gcm(key, iv).encrypt(utf8ToBytes(plaintext))
    const tag = sealed.subarray(sealed.length - GCM_TAG_LEN)
    const ciphertext = sealed.subarray(0, sealed.length - GCM_TAG_LEN)

    return {
      version: 1,
      salt: bytesToHex(salt),
      iv: bytesToHex(iv),
      tag: bytesToHex(tag),
      ciphertext: bytesToHex(ciphertext),
      scryptN: resolved.N,
      scryptR: resolved.r,
      scryptP: resolved.p
    }
  } finally {
    clean(key)
  }
}

/**
 * Decrypts an encrypted payload using a pre-derived key.
 *
 * @param {EncryptedPayload} payload - The encrypted payload.
 * @param {Uint8Array} key - The 32-byte AES key.
 * @returns {string} The decrypted plaintext.
 */
export function decryptWithKey (payload, key) {
  if (payload.version !== 1) {
    throw new Error(`Unsupported keyring version: ${payload.version}`)
  }
  const iv = hexToBytes(payload.iv)
  const tag = hexToBytes(payload.tag)
  const ciphertext = hexToBytes(payload.ciphertext)
  const sealed = new Uint8Array(ciphertext.length + tag.length)
  sealed.set(ciphertext)
  sealed.set(tag, ciphertext.length)
  return bytesToUtf8(gcm(key, iv).decrypt(sealed))
}

/**
 * Decrypts an encrypted payload using a password.
 *
 * @param {EncryptedPayload} payload - The encrypted payload.
 * @param {string} password - The passphrase used to derive the key.
 * @returns {string} The decrypted plaintext.
 * @throws {Error} If the payload version is not supported.
 * @throws {Error} If the scrypt parameters are invalid, or exceed the supported limits (r <= 32, p <= 4, 128 * r * N <= 256 MiB).
 * @throws {Error} If the password is wrong or the payload was tampered with.
 */
export function decrypt (payload, password) {
  if (payload.version !== 1) {
    throw new Error(`Unsupported keyring version: ${payload.version}`)
  }
  const salt = hexToBytes(payload.salt)
  const key = deriveKey(password, salt, payload)
  try {
    return decryptWithKey(payload, key)
  } finally {
    clean(key)
  }
}

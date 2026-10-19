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

import { split as shamirSplit, combine as shamirCombine } from 'shamir-secret-sharing'
import { mnemonicToEntropy, entropyToMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes, clean } from '@noble/hashes/utils.js'

const MAX_SHARES = 255

// Bytes of a SHA-256 digest prefixed to the entropy before splitting. Shamir
// shares are otherwise unauthenticated, so this lets combine detect a wrong or
// corrupted share set (error detection, not defense against forged shares).
const CHECKSUM_LEN = 4

/**
 * Prefixes the entropy with a truncated SHA-256 checksum.
 * @param {Uint8Array} entropy
 * @returns {Uint8Array} `checksum || entropy`
 */
function attachChecksum (entropy) {
  const secret = new Uint8Array(CHECKSUM_LEN + entropy.length)
  secret.set(sha256(entropy).subarray(0, CHECKSUM_LEN))
  secret.set(entropy, CHECKSUM_LEN)
  return secret
}

/**
 * Separates a reconstructed `checksum || entropy` secret and verifies the checksum.
 * @param {Uint8Array} secret
 * @returns {Uint8Array} The verified entropy (a view into `secret`).
 * @throws If the secret is too short or the checksum does not match.
 */
function verifyChecksum (secret) {
  if (secret.length <= CHECKSUM_LEN) throw new Error('reconstructed secret is too short')
  const entropy = secret.subarray(CHECKSUM_LEN)
  const expected = sha256(entropy).subarray(0, CHECKSUM_LEN)
  for (let i = 0; i < CHECKSUM_LEN; i++) {
    if (secret[i] !== expected[i]) throw new Error('checksum mismatch')
  }
  return entropy
}

/**
 * @typedef {Object} SplitOptions
 * @property {number} shares - Total number of shares to create (n). 2..255.
 * @property {number} threshold - Minimum shares needed to reconstruct (k). 2..shares.
 */

/**
 * @param {SplitOptions} [options]
 * @returns {{ shares: number, threshold: number }}
 */
function validateSplitOptions (options) {
  if (!options || typeof options !== 'object') {
    throw new Error('Options must be an object with shares and threshold properties')
  }

  const { shares, threshold } = options

  if (!Number.isInteger(shares)) throw new Error('shares must be an integer')
  if (!Number.isInteger(threshold)) throw new Error('threshold must be an integer')
  if (shares < 2) throw new Error('shares must be at least 2')
  if (threshold < 2) throw new Error('threshold must be at least 2')
  if (threshold > shares) throw new Error('threshold cannot be greater than shares')
  if (shares > MAX_SHARES) throw new Error(`shares cannot exceed ${MAX_SHARES}`)

  return { shares, threshold }
}

/**
 * Validates the shares array and returns lowercase-normalized hex strings.
 * Accepts either case; `hexToBytes` (via the native `Uint8Array.fromHex`) only
 * decodes lowercase, so we normalize here to keep behavior runtime-independent.
 *
 * @param {string[]} shares
 * @returns {string[]}
 */
function validateShares (shares) {
  if (!Array.isArray(shares)) throw new Error('Shares must be an array')
  if (shares.length < 2) throw new Error('At least 2 shares are required to reconstruct the secret')

  return shares.map((share, i) => {
    if (typeof share !== 'string') throw new Error(`Share at index ${i} must be a string`)
    if (share.length === 0 || share.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(share)) {
      throw new Error(`Share at index ${i} is not a valid hex string`)
    }
    if (share.endsWith('00')) {
      throw new Error(`Share at index ${i} has an invalid index byte`)
    }
    return share.toLowerCase()
  })
}

/**
 * Splits a BIP-39 mnemonic into hex-encoded Shamir shares.
 *
 * The mnemonic is decoded to its raw BIP-39 entropy (16-32 bytes) before
 * splitting, so an invalid checksum or a non-wordlist word is rejected here.
 * A 4-byte integrity checksum is prefixed to the entropy so that a wrong or
 * corrupted share set is rejected by {@link combineMnemonic}; the phrase itself
 * is re-derived on combine, not stored in the shares.
 *
 * @param {string} mnemonic - A valid BIP-39 mnemonic (12, 15, 18, 21, or 24 words).
 * @param {SplitOptions} options - Split configuration.
 * @returns {Promise<string[]>} Hex-encoded shares, `options.shares` of them.
 */
export async function splitMnemonic (mnemonic, options) {
  const { shares, threshold } = validateSplitOptions(options)
  if (typeof mnemonic !== 'string') throw new Error('Mnemonic must be a string')

  const normalized = mnemonic.trim().replace(/\s+/g, ' ')
  let entropy
  try {
    entropy = mnemonicToEntropy(normalized, wordlist)
  } catch {
    throw new Error('Invalid mnemonic: expected a valid BIP-39 phrase')
  }

  let secret
  try {
    secret = attachChecksum(entropy)
    const shareArrays = await shamirSplit(secret, shares, threshold)
    return shareArrays.map((share) => bytesToHex(share))
  } finally {
    clean(entropy)
    if (secret) clean(secret)
  }
}

/**
 * Reconstructs a BIP-39 mnemonic from Shamir shares. At least `threshold`
 * shares must be supplied.
 *
 * The 4-byte checksum embedded at split time is verified here, so wrong,
 * corrupted, or insufficient shares are rejected instead of returning an
 * incorrect phrase. This is error detection, not authentication against
 * maliciously crafted shares.
 *
 * @param {string[]} shares - Hex-encoded shares produced by {@link splitMnemonic}.
 * @returns {Promise<string>} The reconstructed BIP-39 mnemonic.
 * @throws {Error} If a share has a zero index byte, which would make it dictate the reconstructed secret.
 */
export async function combineMnemonic (shares) {
  const normalized = validateShares(shares)
  const shareArrays = normalized.map((share) => hexToBytes(share))

  let secret
  try {
    secret = await shamirCombine(shareArrays)
    return entropyToMnemonic(verifyChecksum(secret), wordlist)
  } catch {
    throw new Error('Invalid shares: could not reconstruct a valid mnemonic')
  } finally {
    if (secret) clean(secret)
  }
}

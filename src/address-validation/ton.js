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

import { base64 } from '@scure/base'

/** @typedef {import("./types.js").AddressValidationFailure} TonAddressValidationFailure */
/** @typedef {{ success: true, type: 'ton' }} TonAddressValidationSuccess */
/** @typedef {TonAddressValidationSuccess | TonAddressValidationFailure} TonAddressValidationResult */

// Raw form: signed workchain id + 64-hex-char (32-byte) account id.
const RAW_RE = /^-?\d+:[0-9a-f]{64}$/i

// User-friendly form: base64 of 1-byte tag + 1-byte workchain + 32-byte hash + 2-byte CRC16.
const FRIENDLY_LENGTH = 48
const DECODED_LENGTH = 36
const TAG_TEST_ONLY = 0x80
const TAG_BOUNCEABLE = 0x11
const TAG_NON_BOUNCEABLE = 0x51

/**
 * Computes a CRC16-CCITT (XMODEM) checksum: polynomial 0x1021, initial value 0.
 * @param {Uint8Array} data
 * @returns {number}
 */
function _crc16 (data) {
  let crc = 0
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i] << 8
    for (let bit = 0; bit < 8; bit++) {
      crc = (crc & 0x8000) ? (crc << 1) ^ 0x1021 : crc << 1
      crc &= 0xffff
    }
  }
  return crc
}

/**
 * Validates a TON address in either raw (`<workchain>:<hex>`) or user-friendly
 * (base64/base64url) form. User-friendly addresses are verified against their
 * CRC16-CCITT checksum; raw addresses carry no checksum, so only their
 * structure is validated.
 *
 * @param {string} address The address to validate.
 * @returns {TonAddressValidationResult}
 */
export function validateTonAddress (address) {
  if (typeof address !== 'string') {
    return { success: false, reason: 'INVALID_FORMAT' }
  }
  const trimmed = address.trim()
  if (trimmed.length === 0) {
    return { success: false, reason: 'EMPTY_ADDRESS' }
  }

  if (trimmed.includes(':')) {
    return RAW_RE.test(trimmed)
      ? { success: true, type: 'ton' }
      : { success: false, reason: 'INVALID_FORMAT' }
  }

  if (trimmed.length !== FRIENDLY_LENGTH) {
    return { success: false, reason: 'INVALID_FORMAT' }
  }

  let bytes
  try {
    // Normalize URL-safe base64 (`-`/`_`) to the standard alphabet before decoding.
    bytes = base64.decode(trimmed.replace(/-/g, '+').replace(/_/g, '/'))
  } catch (e) {
    return { success: false, reason: 'INVALID_FORMAT' }
  }
  if (bytes.length !== DECODED_LENGTH) {
    return { success: false, reason: 'INVALID_FORMAT' }
  }

  const tag = bytes[0] & ~TAG_TEST_ONLY
  if (tag !== TAG_BOUNCEABLE && tag !== TAG_NON_BOUNCEABLE) {
    return { success: false, reason: 'INVALID_FORMAT' }
  }
  if (_crc16(bytes.subarray(0, 34)) !== ((bytes[34] << 8) | bytes[35])) {
    return { success: false, reason: 'INVALID_CHECKSUM' }
  }

  return { success: true, type: 'ton' }
}

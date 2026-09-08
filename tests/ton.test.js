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

import { validateTonAddress } from '../src/address-validation/ton'

// Canonical vectors from the TON documentation, all four sharing the same
// account id 0:ca6e321c7cce9ecedf0a8ca2492ec8592494aa5fb5ce0387dff96ef6af982a3e
const BOUNCEABLE = 'EQDKbjIcfM6ezt8KjKJJLshZJJSqX7XOA4ff-W72r5gqPrHF'
const NON_BOUNCEABLE = 'UQDKbjIcfM6ezt8KjKJJLshZJJSqX7XOA4ff-W72r5gqPuwA'
const BOUNCEABLE_TESTNET = 'kQDKbjIcfM6ezt8KjKJJLshZJJSqX7XOA4ff-W72r5gqPgpP'
const NON_BOUNCEABLE_TESTNET = '0QDKbjIcfM6ezt8KjKJJLshZJJSqX7XOA4ff-W72r5gqPleK'
const RAW = '0:ca6e321c7cce9ecedf0a8ca2492ec8592494aa5fb5ce0387dff96ef6af982a3e'

const ok = { success: true, type: 'ton' }

describe('validateTonAddress', () => {
  test('accepts user-friendly addresses (bounceable, non-bounceable, testnet)', () => {
    expect(validateTonAddress(BOUNCEABLE)).toEqual(ok)
    expect(validateTonAddress(NON_BOUNCEABLE)).toEqual(ok)
    expect(validateTonAddress(BOUNCEABLE_TESTNET)).toEqual(ok)
    expect(validateTonAddress(NON_BOUNCEABLE_TESTNET)).toEqual(ok)
  })

  test('accepts the standard base64 alphabet (+/) as well as base64url (-_)', () => {
    const standard = BOUNCEABLE.replace(/-/g, '+').replace(/_/g, '/')
    expect(standard).toContain('+')
    expect(validateTonAddress(standard)).toEqual(ok)
  })

  test('accepts raw addresses (basechain, masterchain, uppercase hex)', () => {
    expect(validateTonAddress(RAW)).toEqual(ok)
    expect(validateTonAddress(`-1:${RAW.split(':')[1]}`)).toEqual(ok)
    expect(validateTonAddress(RAW.toUpperCase())).toEqual(ok)
  })

  test('trims surrounding whitespace', () => {
    expect(validateTonAddress(`  ${BOUNCEABLE}  `)).toEqual(ok)
  })

  test('returns INVALID_CHECKSUM when the checksum is altered', () => {
    expect(validateTonAddress(BOUNCEABLE.slice(0, -1) + 'G')).toEqual({ success: false, reason: 'INVALID_CHECKSUM' })
  })

  test('returns INVALID_FORMAT for structurally invalid addresses', () => {
    expect(validateTonAddress('A' + BOUNCEABLE.slice(1))).toEqual({ success: false, reason: 'INVALID_FORMAT' }) // bad tag
    expect(validateTonAddress(BOUNCEABLE.slice(0, -1))).toEqual({ success: false, reason: 'INVALID_FORMAT' }) // wrong length
    expect(validateTonAddress(BOUNCEABLE.slice(0, -1) + '*')).toEqual({ success: false, reason: 'INVALID_FORMAT' }) // bad base64
    expect(validateTonAddress('abc:' + RAW.split(':')[1])).toEqual({ success: false, reason: 'INVALID_FORMAT' }) // bad workchain
    expect(validateTonAddress('0:ca6e321c')).toEqual({ success: false, reason: 'INVALID_FORMAT' }) // short hash
    expect(validateTonAddress(`${RAW}:extra`)).toEqual({ success: false, reason: 'INVALID_FORMAT' }) // extra colon
  })

  test('returns EMPTY_ADDRESS for empty or whitespace-only input', () => {
    expect(validateTonAddress('')).toEqual({ success: false, reason: 'EMPTY_ADDRESS' })
    expect(validateTonAddress('   ')).toEqual({ success: false, reason: 'EMPTY_ADDRESS' })
  })

  test('returns INVALID_FORMAT for non-string input', () => {
    expect(validateTonAddress(null)).toEqual({ success: false, reason: 'INVALID_FORMAT' })
    expect(validateTonAddress(undefined)).toEqual({ success: false, reason: 'INVALID_FORMAT' })
    expect(validateTonAddress(123)).toEqual({ success: false, reason: 'INVALID_FORMAT' })
  })
})

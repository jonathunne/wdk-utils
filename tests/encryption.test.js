import { jest } from '@jest/globals'
import * as cipherUtils from '@noble/ciphers/utils.js'

const queued = []

jest.unstable_mockModule('@noble/ciphers/utils.js', () => ({
  ...cipherUtils,
  randomBytes: (n) => (queued.length > 0 ? queued.shift() : cipherUtils.randomBytes(n))
}))

const { encrypt, decrypt, deriveKey } = await import('../src/encryption/index.js')

const PHRASE =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

describe('encryption', () => {
  it('encrypts deterministically with pinned salt+iv', () => {
    queued.push(
      cipherUtils.hexToBytes('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'),
      cipherUtils.hexToBytes('aabbccddeeff001122334455')
    )

    const payload = encrypt(PHRASE, 'testpassword123')

    expect(payload).toEqual({
      version: 1,
      salt: '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
      iv: 'aabbccddeeff001122334455',
      tag: '04247a2e56402b743718b1dd3c242623',
      ciphertext:
        '2ba561282f7a73e748caa33cd74711c0b468c5af1d3144ed78beea60bb18acada504eade33cc207265b3750d22648e449f96774ba5946a2f594369fc7ba42f64b432b958e98f3cda4853c04ed0e6ef7fd205b7958822c7a3d0ea7a7383',
      scryptN: 65536,
      scryptR: 8,
      scryptP: 1
    })
    expect(decrypt(payload, 'testpassword123')).toBe(PHRASE)
  })

  it('round-trips encrypt/decrypt correctly', () => {
    const payload = encrypt(PHRASE, 'testpassword123')
    expect(payload.version).toBe(1)
    expect(decrypt(payload, 'testpassword123')).toBe(PHRASE)
  })

  it('rejects wrong password', () => {
    const payload = encrypt('secret data', 'correctpassword')
    expect(() => decrypt(payload, 'wrongpassword')).toThrow()
  })

  it('produces different ciphertexts for same plaintext', () => {
    const p1 = encrypt('test data', 'password')
    const p2 = encrypt('test data', 'password')
    expect(p1.ciphertext).not.toBe(p2.ciphertext)
    expect(p1.salt).not.toBe(p2.salt)
  })

  it('rejects unsupported version', () => {
    const payload = encrypt('test', 'pass')
    const badPayload = { ...payload, version: 2 }
    expect(() => decrypt(badPayload, 'pass')).toThrow(/Unsupported keyring version/)
  })

  it('decrypts legacy payloads without stored scrypt params', () => {
    const payload = encrypt(PHRASE, 'testpassword123')
    const { scryptN, scryptR, scryptP, ...legacyPayload } = payload
    expect(decrypt(legacyPayload, 'testpassword123')).toBe(PHRASE)
  })

  it('round-trips custom scrypt params', () => {
    const payload = encrypt(PHRASE, 'testpassword123', { N: 2 ** 15, r: 8, p: 1 })
    expect(payload.scryptN).toBe(32768)
    expect(decrypt(payload, 'testpassword123')).toBe(PHRASE)
  })

  it.each([
    ['N=2^18 r=8 p=1 (256 MiB)', { N: 2 ** 18, r: 8, p: 1 }, 'bf0d9afa730ca6e7a031e6c4b39f9555e75e3f315347b93cfeed5d39da818f3c'],
    ['N=2^17 r=16 p=1 (256 MiB)', { N: 2 ** 17, r: 16, p: 1 }, '6205baca4a350cf716d6d67bbb5e32168a15174df91f493ac4cffef324e3aa05'],
    ['N=2^16 r=32 p=4 (largest r and p)', { N: 2 ** 16, r: 32, p: 4 }, 'e73797c143d6b9733e33e01ceab6ef733b5af440e8a157b1f9a38deca46b4397']
  ])('derives with %s, the largest supported scrypt params', (_, params, expectedKey) => {
    const key = deriveKey('testpassword123', new Uint8Array(32), params)
    expect(cipherUtils.bytesToHex(key)).toBe(expectedKey)
  })

  it.each([
    ['N above the memory limit', { N: 2 ** 19, r: 8, p: 1 }],
    ['r above the limit', { N: 2 ** 16, r: 33, p: 1 }],
    ['p above the limit', { N: 2 ** 16, r: 8, p: 5 }],
    ['a small N with a huge p', { N: 1024, r: 8, p: 4000 }]
  ])('rejects encrypting with %s', (_, params) => {
    expect(() => encrypt(PHRASE, 'testpassword123', params)).toThrow('Unsupported scrypt parameters: r must not exceed 32, p must not exceed 4 and 128 * r * N must not exceed 268435456 bytes')
  })

  it.each([
    ['scryptN above the memory limit', { scryptN: 2 ** 19 }],
    ['scryptR above the limit', { scryptR: 2 ** 20 }],
    ['scryptP above the limit', { scryptP: 4000 }]
  ])('rejects a payload with %s before deriving the key', (_, override) => {
    const payload = { ...encrypt(PHRASE, 'testpassword123'), ...override }
    expect(() => decrypt(payload, 'testpassword123')).toThrow('Unsupported scrypt parameters: r must not exceed 32, p must not exceed 4 and 128 * r * N must not exceed 268435456 bytes')
  })

  it('throws an actionable error when crypto.getRandomValues is unavailable', () => {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto')
    Object.defineProperty(globalThis, 'crypto', { value: {}, configurable: true })
    try {
      expect(() => encrypt(PHRASE, 'testpassword123')).toThrow(/react-native-get-random-values/)
    } finally {
      Object.defineProperty(globalThis, 'crypto', descriptor)
    }
  })

  it('does not require crypto.getRandomValues to decrypt', () => {
    const payload = encrypt(PHRASE, 'testpassword123')

    const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto')
    Object.defineProperty(globalThis, 'crypto', { value: {}, configurable: true })
    try {
      expect(decrypt(payload, 'testpassword123')).toBe(PHRASE)
    } finally {
      Object.defineProperty(globalThis, 'crypto', descriptor)
    }
  })
})

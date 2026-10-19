import { splitMnemonic, combineMnemonic } from '../src/shamir/index.js'
import { mnemonicToEntropy } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex } from '@noble/hashes/utils.js'

// Well-known BIP-39 test vectors (all-`abandon` prefixes with valid checksums).
// NOT for production use.
const MNEMONICS = {
  12: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  15: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address',
  18: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent',
  21: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon admit',
  24: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art'
}

const SCHEMES = [
  { shares: 2, threshold: 2 },
  { shares: 5, threshold: 3 },
  { shares: 10, threshold: 5 }
]

// Deterministic subset picker: take `k` evenly-spread shares from the set.
function pick (shares, k) {
  const step = Math.floor(shares.length / k)
  const subset = []
  for (let i = 0; i < k; i++) subset.push(shares[i * step])
  return subset
}

describe('shamir', () => {
  describe('round-trip across word lengths and schemes', () => {
    for (const [words, mnemonic] of Object.entries(MNEMONICS)) {
      for (const { shares, threshold } of SCHEMES) {
        it(`reconstructs a ${words}-word mnemonic under ${threshold}-of-${shares}`, async () => {
          const parts = await splitMnemonic(mnemonic, { shares, threshold })

          expect(parts).toHaveLength(shares)
          parts.forEach((part) => expect(part).toMatch(/^[0-9a-f]+$/))

          const recovered = await combineMnemonic(pick(parts, threshold))
          expect(recovered).toBe(mnemonic)
        })
      }
    }
  })

  describe('combineMnemonic', () => {
    it('reconstructs from any threshold-sized subset', async () => {
      const mnemonic = MNEMONICS[12]
      const parts = await splitMnemonic(mnemonic, { shares: 5, threshold: 3 })

      expect(await combineMnemonic([parts[0], parts[2], parts[4]])).toBe(mnemonic)
      expect(await combineMnemonic([parts[1], parts[3], parts[4]])).toBe(mnemonic)
    })

    it('reconstructs from all shares', async () => {
      const mnemonic = MNEMONICS[24]
      const parts = await splitMnemonic(mnemonic, { shares: 3, threshold: 2 })
      expect(await combineMnemonic(parts)).toBe(mnemonic)
    })
  })

  describe('share size is entropy-based', () => {
    it('produces 21-byte shares for a 12-word mnemonic (16-byte entropy + 4-byte checksum + index)', async () => {
      const parts = await splitMnemonic(MNEMONICS[12], { shares: 3, threshold: 2 })
      parts.forEach((part) => expect(part.length / 2).toBe(21))
    })

    it('produces 37-byte shares for a 24-word mnemonic (32-byte entropy + 4-byte checksum + index)', async () => {
      const parts = await splitMnemonic(MNEMONICS[24], { shares: 3, threshold: 2 })
      parts.forEach((part) => expect(part.length / 2).toBe(37))
    })
  })

  describe('integrity checksum on combine', () => {
    it('rejects a corrupted share instead of returning a wrong phrase', async () => {
      const parts = await splitMnemonic(MNEMONICS[12], { shares: 3, threshold: 2 })
      const corrupted = [...parts]
      corrupted[0] = (corrupted[0][0] === '0' ? '1' : '0') + corrupted[0].slice(1)
      await expect(combineMnemonic([corrupted[0], corrupted[1]])).rejects.toThrow('Invalid shares')
    })

    it('rejects a below-threshold share subset', async () => {
      const parts = await splitMnemonic(MNEMONICS[12], { shares: 5, threshold: 3 })
      await expect(combineMnemonic([parts[0], parts[1]])).rejects.toThrow('Invalid shares')
    })
  })

  describe('mnemonic normalization on split', () => {
    it('tolerates leading, trailing, and repeated whitespace', async () => {
      const messy = `\t  ${MNEMONICS[12].replace(/ /g, '   ')}\n`
      const parts = await splitMnemonic(messy, { shares: 3, threshold: 2 })
      expect(await combineMnemonic(parts)).toBe(MNEMONICS[12])
    })
  })

  describe('mnemonic validation on split', () => {
    it('rejects a mnemonic with a bad checksum', async () => {
      const badChecksum = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon'
      await expect(splitMnemonic(badChecksum, { shares: 3, threshold: 2 })).rejects.toThrow('Invalid mnemonic')
    })

    it('rejects a mnemonic containing a non-wordlist word', async () => {
      const nonWordlist = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzzzzz'
      await expect(splitMnemonic(nonWordlist, { shares: 3, threshold: 2 })).rejects.toThrow('Invalid mnemonic')
    })

    it('rejects an invalid word count', async () => {
      await expect(splitMnemonic('abandon abandon abandon', { shares: 3, threshold: 2 })).rejects.toThrow('Invalid mnemonic')
    })

    it('rejects a non-string mnemonic', async () => {
      await expect(splitMnemonic(12345, { shares: 3, threshold: 2 })).rejects.toThrow('Mnemonic must be a string')
    })
  })

  describe('option validation on split', () => {
    const mnemonic = MNEMONICS[12]

    it('requires an options object', async () => {
      await expect(splitMnemonic(mnemonic)).rejects.toThrow('Options must be an object')
    })

    it('rejects non-integer shares', async () => {
      await expect(splitMnemonic(mnemonic, { shares: 3.5, threshold: 2 })).rejects.toThrow('shares must be an integer')
    })

    it('rejects shares below 2', async () => {
      await expect(splitMnemonic(mnemonic, { shares: 1, threshold: 1 })).rejects.toThrow('shares must be at least 2')
    })

    it('rejects threshold below 2', async () => {
      await expect(splitMnemonic(mnemonic, { shares: 3, threshold: 1 })).rejects.toThrow('threshold must be at least 2')
    })

    it('rejects threshold greater than shares', async () => {
      await expect(splitMnemonic(mnemonic, { shares: 3, threshold: 5 })).rejects.toThrow('threshold cannot be greater than shares')
    })

    it('rejects shares above 255', async () => {
      await expect(splitMnemonic(mnemonic, { shares: 256, threshold: 2 })).rejects.toThrow('shares cannot exceed 255')
    })
  })

  describe('share validation on combine', () => {
    it('rejects a non-array input', async () => {
      await expect(combineMnemonic('not-an-array')).rejects.toThrow('Shares must be an array')
    })

    it('rejects fewer than 2 shares', async () => {
      const parts = await splitMnemonic(MNEMONICS[12], { shares: 5, threshold: 3 })
      await expect(combineMnemonic([parts[0]])).rejects.toThrow('At least 2 shares are required')
    })

    it('rejects a non-string share', async () => {
      await expect(combineMnemonic(['abcd', 1234, 'ef01'])).rejects.toThrow('must be a string')
    })

    it('rejects an invalid hex share', async () => {
      await expect(combineMnemonic(['abcd', 'xyz9', 'ef01'])).rejects.toThrow('not a valid hex string')
    })

    it('accepts uppercase hex shares', async () => {
      const parts = await splitMnemonic(MNEMONICS[12], { shares: 3, threshold: 2 })
      const upper = parts.map((part) => part.toUpperCase())
      expect(await combineMnemonic(upper)).toBe(MNEMONICS[12])
    })

    describe('share with a zero index byte', () => {
      const FORGED_MNEMONIC = 'legal winner thank year wave sausage worth useful legal winner thank yellow'
      const forgedEntropy = mnemonicToEntropy(FORGED_MNEMONIC, wordlist)
      const FORGED_SHARE = bytesToHex(sha256(forgedEntropy).subarray(0, 4)) + bytesToHex(forgedEntropy) + '00'

      it('is rejected before combining', async () => {
        const parts = await splitMnemonic(MNEMONICS[12], { shares: 3, threshold: 2 })
        await expect(combineMnemonic([FORGED_SHARE, parts[0]])).rejects.toThrow('Share at index 0 has an invalid index byte')
      })

      it('is rejected at any position, even alongside a full honest threshold', async () => {
        const parts = await splitMnemonic(MNEMONICS[12], { shares: 3, threshold: 2 })
        await expect(combineMnemonic([parts[0], parts[1], FORGED_SHARE])).rejects.toThrow('Share at index 2 has an invalid index byte')
      })
    })

    it('rejects duplicate shares', async () => {
      const parts = await splitMnemonic(MNEMONICS[12], { shares: 3, threshold: 2 })
      await expect(combineMnemonic([parts[0], parts[0]])).rejects.toThrow('Invalid shares')
    })

    it('rejects shares of differing lengths', async () => {
      const short = await splitMnemonic(MNEMONICS[12], { shares: 2, threshold: 2 })
      const long = await splitMnemonic(MNEMONICS[24], { shares: 2, threshold: 2 })
      await expect(combineMnemonic([short[0], long[0]])).rejects.toThrow('Invalid shares')
    })
  })
})

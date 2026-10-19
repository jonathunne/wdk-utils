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
export function splitMnemonic(mnemonic: string, options: SplitOptions): Promise<string[]>;
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
export function combineMnemonic(shares: string[]): Promise<string>;
export type SplitOptions = {
    /**
     * - Total number of shares to create (n). 2..255.
     */
    shares: number;
    /**
     * - Minimum shares needed to reconstruct (k). 2..shares.
     */
    threshold: number;
};

/**
 * Validates a TON address in either raw (`<workchain>:<hex>`) or user-friendly
 * (base64/base64url) form. User-friendly addresses are verified against their
 * CRC16-CCITT checksum; raw addresses carry no checksum, so only their
 * structure is validated.
 *
 * @param {string} address The address to validate.
 * @returns {TonAddressValidationResult}
 */
export function validateTonAddress(address: string): TonAddressValidationResult;
export type TonAddressValidationFailure = import("./types.js").AddressValidationFailure;
export type TonAddressValidationSuccess = {
    success: true;
    type: "ton";
};
export type TonAddressValidationResult = TonAddressValidationSuccess | TonAddressValidationFailure;

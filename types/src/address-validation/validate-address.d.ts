/**
 * Validates an address for the chain identified by a CAIP-2 chain id.
 * Dispatches to the chain-specific validator and returns its result,
 * including chain-specific fields such as `type` and `network`.
 *
 * Bitcoin and Spark addresses encode their network, so for bip122 and spark
 * chain ids the reference selects the expected network and a mismatching
 * address fails with NETWORK_MISMATCH — as does a missing or unknown
 * reference, since the expected network cannot be confirmed. An address
 * matches when the expected network is among its compatible networks
 * (some formats are shared: legacy testnet Bitcoin addresses are also
 * valid on regtest, and Spark L1 deposit addresses for testnet/signet
 * and regtest/local share their Bitcoin formats).
 *
 * @param {string} chainId - A CAIP-2 chain id (e.g. "eip155:1") or a bare chain namespace (e.g. "eip155").
 * @param {string} address - The address to validate.
 * @returns {ValidateAddressResult} The chain validator's result; INVALID_CHAIN_ID for a malformed chain id, UNSUPPORTED_CHAIN when the chain namespace has no validator.
 */
export function validateAddress(chainId: string, address: string): ValidateAddressResult;
export type ValidateAddressResult = import("./bitcoin.js").BtcAddressValidationResult | import("./evm.js").EvmAddressValidationResult | import("./solana.js").SolanaAddressValidationResult | import("./spark.js").SparkAddressValidationResult | import("./ton.js").TonAddressValidationResult | import("./tron.js").TronAddressValidationResult | import("./types.js").AddressValidationFailure;

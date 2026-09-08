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

import { validateBitcoinAddress } from './bitcoin.js'
import { validateEVMAddress } from './evm.js'
import { validateSolanaAddress } from './solana.js'
import { validateSparkAddress } from './spark.js'
import { validateTonAddress } from './ton.js'
import { validateTronAddress } from './tron.js'

/**
 * @typedef {import("./bitcoin.js").BtcAddressValidationResult | import("./evm.js").EvmAddressValidationResult | import("./solana.js").SolanaAddressValidationResult | import("./spark.js").SparkAddressValidationResult | import("./ton.js").TonAddressValidationResult | import("./tron.js").TronAddressValidationResult | import("./types.js").AddressValidationFailure} ValidateAddressResult
 */

/** Address validators by CAIP-2 chain namespace. */
const VALIDATORS = {
  bip122: validateBitcoinAddress,
  eip155: validateEVMAddress,
  solana: validateSolanaAddress,
  spark: validateSparkAddress,
  ton: validateTonAddress,
  tron: validateTronAddress
}

/** CAIP-2 chain id: a namespace, optionally followed by a ":reference". */
const CHAIN_ID_RE = /^[-a-z0-9]{3,8}(:[-_a-zA-Z0-9]{1,32})?$/

/** bip122 chain references (genesis block hashes) → Bitcoin network label. */
const BITCOIN_NETWORKS = {
  '000000000019d6689c085ae165831e93': 'bitcoin',
  '000000000933ea01ad0ee984209779ba': 'testnet',
  '0f9188f13cb7b2c71f2a335e3a4fc328': 'regtest'
}

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
export function validateAddress (chainId, address) {
  if (typeof chainId !== 'string' || !CHAIN_ID_RE.test(chainId)) {
    return { success: false, reason: 'INVALID_CHAIN_ID' }
  }

  const [namespace, reference] = chainId.split(':')
  const validate = VALIDATORS[namespace]
  if (!validate) return { success: false, reason: 'UNSUPPORTED_CHAIN' }

  const result = validate(address)
  if (!result.success) return result

  if (namespace === 'bip122' && !result.compatibleNetworks.includes(BITCOIN_NETWORKS[reference])) {
    return { success: false, reason: 'NETWORK_MISMATCH' }
  }
  if (namespace === 'spark' && !result.compatibleNetworks.includes(reference)) {
    return { success: false, reason: 'NETWORK_MISMATCH' }
  }
  return result
}

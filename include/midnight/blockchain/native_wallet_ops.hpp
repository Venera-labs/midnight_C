#pragma once

#include "midnight/blockchain/midnight_adapter.hpp"
#include <string>
#include <cstdint>

namespace midnight::blockchain
{

    /**
     * @brief Result of a native (no-Node.js) tNIGHT transfer
     */
    struct NativeTransferResult
    {
        bool success = false;
        std::string txid;
        std::string source_address;
        std::string destination_address;
        std::string amount;
        uint64_t fee = 0;
        uint64_t balance_before = 0;
        std::string error;
    };

    /**
     * @brief Result of a native wallet state query
     */
    struct NativeWalletStateResult
    {
        bool success = false;
        std::string address;
        uint64_t unshielded_balance = 0;
        uint64_t utxo_count = 0;
        std::string error;
    };

    /**
     * @brief Transfer tNIGHT using pure C++ (no Node.js bridge required)
     *
     * This function performs a complete transfer flow natively:
     * 1. Derives address from private key
     * 2. Queries UTXOs via Midnight Node RPC
     * 3. Builds CBOR-serialized transaction
     * 4. Signs with Ed25519
     * 5. Submits to network
     *
     * @param blockchain Connected MidnightBlockchain instance
     * @param private_key_hex Ed25519 private key (64 bytes hex, optional 0x prefix)
     * @param to_address Destination Midnight address (Bech32m format)
     * @param amount Amount to transfer in basic units
     * @return NativeTransferResult with txid on success, error on failure
     */
    NativeTransferResult transfer_night_native(
        MidnightBlockchain &blockchain,
        const std::string &private_key_hex,
        const std::string &to_address,
        uint64_t amount);

    /**
     * @brief Query wallet state using pure C++ (no Node.js bridge required)
     *
     * Queries the Midnight Node RPC for UTXOs at the given address
     * and computes the total unshielded balance.
     *
     * @param blockchain Connected MidnightBlockchain instance
     * @param address Midnight address to query (Bech32m format)
     * @return NativeWalletStateResult with balance and UTXO count
     */
    NativeWalletStateResult query_wallet_state_native(
        MidnightBlockchain &blockchain,
        const std::string &address);

} // namespace midnight::blockchain

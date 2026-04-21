#pragma once

#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <map>

namespace midnight::network
{
    class MidnightNodeRPC;
}

namespace midnight::blockchain
{

    class Transaction;

    /**
     * @brief Result type for blockchain operations
     */
    struct Result
    {
        bool success;
        std::string error_message;
        std::string result;
    };

    /**
     * @brief Protocol parameters for Midnight blockchain
     */
    struct ProtocolParams
    {
        uint64_t min_fee_a = 0;           // Minimum fee coefficient A
        uint64_t min_fee_b = 0;           // Minimum fee coefficient B
        uint64_t price_memory = 0;        // Memory price per unit
        uint64_t price_steps = 0;         // CPU steps price per unit
        uint64_t utxo_cost_per_byte = 0;  // Cost per byte of UTXO
        uint32_t max_tx_size = 0;         // Maximum transaction size
        uint32_t max_block_size = 0;      // Maximum block size
        uint64_t min_pool_cost = 0;       // Minimum pool cost
        uint32_t coins_per_utxo_word = 0; // UTxO entry cost
        uint32_t rpc_timeout_ms = 5000;   // RPC timeout in milliseconds (configurable for IoT)
    };

    /**
     * @brief UTXO (Unspent Transaction Output) for Midnight
     */
    struct UTXO
    {
        std::string tx_hash;                          // Transaction hash in hex (32 bytes)
        uint32_t output_index;                        // Output index in transaction
        std::string address;                          // Recipient address
        uint64_t amount;                              // Amount in basic units
        std::map<std::string, uint64_t> multi_assets; // Multi-assets: {asset_id -> amount}
    };

    /**
     * @brief Midnight Blockchain Manager
     *
     * Manages blockchain operations for the Midnight network including:
     * - Transaction building and validation
     * - Block management and chain state
     * - Address handling
     *
     * Designed with professional architecture patterns for robustness.
     */
    class MidnightBlockchain
    {
    public:
        /**
         * @brief Constructor
         */
        MidnightBlockchain();

        /**
         * @brief Destructor - cleanup resources
         */
        ~MidnightBlockchain();

        /**
         * @brief Initialize blockchain manager with network configuration
         * @param network Network name (testnet, staging, mainnet)
         * @param protocol_params Protocol parameters for transaction building
         */
        void initialize(const std::string &network, const ProtocolParams &protocol_params);

        /**
         * @brief Connect to Midnight node
         * @param node_url Node URL (e.g., "http://localhost:9944")
         * @return True if connection successful
         */
        bool connect(const std::string &node_url);

        /**
         * @brief Create a new address from public key
         * @param public_key Public key in hex format
         * @param network_id Network ID (0=testnet, 1=mainnet)
         * @return Address string or empty on error
         */
        std::string create_address(const std::string &public_key, uint8_t network_id = 0);

        /**
         * @brief Validate Midnight address
         * @param address Address to validate
         * @return True if valid Bech32/Byron address
         */
        static bool validate_address(const std::string &address);

        /**
         * @brief Build transaction using UTXOs
         * @param utxos List of UTXOs to spend
         * @param outputs Map of address->amount for outputs
         * @param change_address Where to send change
         * @return Built transaction or error
         */
        Result build_transaction(
            const std::vector<UTXO> &utxos,
            const std::vector<std::pair<std::string, uint64_t>> &outputs,
            const std::string &change_address);

        /**
         * @brief Sign transaction with private key
         * @param transaction_hex Transaction serialized format
         * @param private_key Private key in hex
         * @return Signed transaction or error
         */
        Result sign_transaction(const std::string &transaction_hex, const std::string &private_key);

        /**
         * @brief Submit transaction to network
         * @param signed_tx Transaction data
         * @return Transaction ID or error
         */
        Result submit_transaction(const std::string &signed_tx);

        /**
         * @brief Query UTXOs for an address
         * @param address Address to query
         * @return List of UTXOs at address
         */
        std::vector<UTXO> query_utxos(const std::string &address);

        /**
         * @brief Get protocol parameters
         * @return ProtocolParams
         */
        ProtocolParams get_protocol_params() const;

        /**
         * @brief Get current chain tip (latest block info)
         * @return Tip information or error
         */
        Result get_chain_tip() const;

        /**
         * @brief Check connection status
         * @return True if connected to network
         */
        bool is_connected() const { return connected_; }

        /**
         * @brief Disconnect from network
         */
        void disconnect();

    private:
        std::string network_;
        std::string node_url_;
        bool connected_ = false;
        ProtocolParams protocol_params_;
        std::unique_ptr<midnight::network::MidnightNodeRPC> rpc_; // RPC client

        // Helper methods
        uint64_t calculate_min_fee(size_t tx_size);
        bool validate_transaction(const Transaction &tx);
    };

} // namespace midnight::blockchain

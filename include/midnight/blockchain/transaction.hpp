#pragma once

#include <string>
#include <vector>
#include <map>
#include <cstdint>

namespace midnight::blockchain
{

    /**
     * @brief Represents a Midnight blockchain transaction
     */
    class Transaction
    {
    public:
        /**
         * @brief Transaction input (UTXO reference)
         */
        struct Input
        {
            std::string tx_hash;   // Previous transaction hash (hex)
            uint32_t output_index; // Output index in previous tx
        };

        /**
         * @brief Transaction output
         */
        struct Output
        {
            std::string address;                                           // Recipient address
            uint64_t amount;                                               // Amount in lovelace
            std::map<std::string, std::map<std::string, uint64_t>> assets; // Multi-assets: policyId -> assetName -> quantity
        };

        /**
         * @brief Certificate for staking operations
         */
        struct Certificate
        {
            enum class Type
            {
                STAKE_KEY_REGISTRATION,
                STAKE_KEY_UNREGISTRATION,
                STAKE_ADDRESS_DELEGATION
            };
            Type type;
            std::string stake_key_hash;
            std::string pool_id; // For delegation
        };

        /**
         * @brief Constructor with transaction ID
         */
        explicit Transaction(const std::string &tx_id = "");

        /**
         * @brief Add input to transaction
         */
        void add_input(const Input &input);

        /**
         * @brief Add output to transaction
         */
        void add_output(const Output &output);

        /**
         * @brief Add certificate (staking cert, etc)
         */
        void add_certificate(const Certificate &cert);

        /**
         * @brief Set transaction fee
         * @param fee Fee amount in basic units
         */
        void set_fee(uint64_t fee);

        /**
         * @brief Get transaction fee
         * @return Fee amount in basic units
         */
        uint64_t get_fee() const { return fee_; }

        /**
         * @brief Set validity interval (block numbers)
         */
        void set_validity(uint64_t invalid_hereafter, uint64_t invalid_before = 0);

        /**
         * @brief Calculate transaction hash (SHA256)
         */
        std::string calculate_hash() const;

        /**
         * @brief Get transaction ID
         */
        const std::string &get_tx_id() const { return tx_id_; }

        /**
         * @brief Get all inputs
         */
        const std::vector<Input> &get_inputs() const { return inputs_; }

        /**
         * @brief Get all outputs
         */
        const std::vector<Output> &get_outputs() const { return outputs_; }

        /**
         * @brief Get certificates
         */
        const std::vector<Certificate> &get_certificates() const { return certificates_; }

        /**
         * @brief Get total input amount (lovelace)
         */
        uint64_t get_total_inputs() const;

        /**
         * @brief Get total output amount (lovelace)
         */
        uint64_t get_total_outputs() const;

        /**
         * @brief Serialize to CBOR hex format for blockchain submission
         */
        std::string to_cbor_hex() const;

        /**
         * @brief Deserialize from CBOR hex format
         */
        static Transaction from_cbor_hex(const std::string &cbor_hex);

        /**
         * @brief Serialize to JSON (CIP-116 format)
         */
        std::string to_json() const;

        /**
         * @brief Get transaction size in bytes (for fee calculation)
         */
        size_t get_size() const;

    private:
        uint64_t calculate_min_fee() const;
        std::string tx_id_;
        std::vector<Input> inputs_;
        std::vector<Output> outputs_;
        std::vector<Certificate> certificates_;
        uint64_t fee_ = 0;
        uint64_t invalid_hereafter_ = 0;
        uint64_t invalid_before_ = 0;
    };

} // namespace midnight::blockchain

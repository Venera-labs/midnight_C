#include "midnight/blockchain/midnight_adapter.hpp"
#include "midnight/blockchain/transaction.hpp"
#include "midnight/core/logger.hpp"
#include "midnight/network/midnight_node_rpc.hpp"
#include "midnight/crypto/ed25519_signer.hpp"
#include <nlohmann/json.hpp>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <algorithm>
#include <array>
#include <vector>
#include <cctype>
#include <cstring>

namespace midnight::blockchain
{

    namespace
    {
        constexpr uint32_t kBech32mConst = 0x2BC830A3;
        constexpr const char *kBech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

        uint32_t bech32_polymod(const std::vector<uint8_t> &values)
        {
            static constexpr uint32_t gen[5] = {0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3};
            uint32_t chk = 1;
            for (auto value : values)
            {
                const uint32_t top = chk >> 25;
                chk = ((chk & 0x1FFFFFF) << 5) ^ value;
                for (int i = 0; i < 5; ++i)
                {
                    chk ^= ((top >> i) & 1) ? gen[i] : 0;
                }
            }
            return chk;
        }

        std::vector<uint8_t> bech32_hrp_expand(const std::string &hrp)
        {
            std::vector<uint8_t> ret;
            ret.reserve(hrp.size() * 2 + 1);
            for (unsigned char c : hrp)
            {
                ret.push_back(c >> 5);
            }
            ret.push_back(0);
            for (unsigned char c : hrp)
            {
                ret.push_back(c & 31);
            }
            return ret;
        }

        std::vector<uint8_t> convert_bits(const uint8_t *data, size_t data_len, int from_bits, int to_bits, bool pad)
        {
            int acc = 0;
            int bits = 0;
            const int maxv = (1 << to_bits) - 1;
            const int max_acc = (1 << (from_bits + to_bits - 1)) - 1;
            std::vector<uint8_t> ret;
            ret.reserve((data_len * from_bits + to_bits - 1) / to_bits);

            for (size_t i = 0; i < data_len; ++i)
            {
                const int value = data[i];
                acc = ((acc << from_bits) | value) & max_acc;
                bits += from_bits;
                while (bits >= to_bits)
                {
                    bits -= to_bits;
                    ret.push_back((acc >> bits) & maxv);
                }
            }

            if (pad)
            {
                if (bits != 0)
                {
                    ret.push_back(static_cast<uint8_t>((acc << (to_bits - bits)) & maxv));
                }
            }
            else if (bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0)
            {
                return {};
            }

            return ret;
        }

        std::string bech32m_encode(const std::string &hrp, const std::array<uint8_t, 32> &payload)
        {
            std::vector<uint8_t> data;
            auto converted = convert_bits(payload.data(), payload.size(), 8, 5, true);
            data.insert(data.end(), converted.begin(), converted.end());

            auto values = bech32_hrp_expand(hrp);
            values.insert(values.end(), data.begin(), data.end());
            values.insert(values.end(), 6, 0);
            const uint32_t polymod = bech32_polymod(values) ^ kBech32mConst;

            std::array<uint8_t, 6> checksum{};
            for (int i = 0; i < 6; ++i)
            {
                checksum[i] = (polymod >> (5 * (5 - i))) & 31;
            }

            std::string out = hrp + "1";
            out.reserve(hrp.size() + 1 + data.size() + checksum.size());
            for (auto v : data)
            {
                out.push_back(kBech32Charset[v]);
            }
            for (auto v : checksum)
            {
                out.push_back(kBech32Charset[v]);
            }
            return out;
        }

        int hex_nibble(char c)
        {
            if (c >= '0' && c <= '9')
            {
                return c - '0';
            }

            const char lower = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (lower >= 'a' && lower <= 'f')
            {
                return 10 + (lower - 'a');
            }

            return -1;
        }

        bool hex_to_fixed_bytes(const std::string &hex_input, uint8_t *out, size_t out_size)
        {
            std::string hex = hex_input;
            if (hex.rfind("0x", 0) == 0 || hex.rfind("0X", 0) == 0)
            {
                hex = hex.substr(2);
            }

            if (hex.size() != (out_size * 2))
            {
                return false;
            }

            for (size_t i = 0; i < out_size; ++i)
            {
                const int hi = hex_nibble(hex[i * 2]);
                const int lo = hex_nibble(hex[i * 2 + 1]);
                if (hi < 0 || lo < 0)
                {
                    return false;
                }

                out[i] = static_cast<uint8_t>((hi << 4) | lo);
            }

            return true;
        }

        bool hex_to_bytes32(const std::string &hex_input, std::array<uint8_t, 32> &out)
        {
            return hex_to_fixed_bytes(hex_input, out.data(), out.size());
        }

        bool has_supported_hrp(const std::string &hrp)
        {
            return hrp.rfind("mn_addr_", 0) == 0 ||
                   hrp.rfind("mn_shield-addr_", 0) == 0 ||
                   hrp.rfind("mn_dust_", 0) == 0;
        }

        bool bech32m_validate_address(const std::string &address)
        {
            if (address.empty())
            {
                return false;
            }

            bool has_lower = false;
            bool has_upper = false;
            std::string lower;
            lower.reserve(address.size());

            for (unsigned char c : address)
            {
                if (c < 33 || c > 126)
                {
                    return false;
                }

                if (std::isalpha(c))
                {
                    if (std::islower(c))
                    {
                        has_lower = true;
                    }
                    else
                    {
                        has_upper = true;
                    }
                }

                lower.push_back(static_cast<char>(std::tolower(c)));
            }

            if (has_lower && has_upper)
            {
                return false;
            }

            const auto sep = lower.rfind('1');
            if (sep == std::string::npos || sep == 0 || sep + 7 > lower.size())
            {
                return false;
            }

            const std::string hrp = lower.substr(0, sep);
            if (!has_supported_hrp(hrp))
            {
                return false;
            }

            std::vector<uint8_t> data;
            data.reserve(lower.size() - sep - 1);
            for (size_t i = sep + 1; i < lower.size(); ++i)
            {
                const char ch = lower[i];
                const char *pos = std::strchr(kBech32Charset, ch);
                if (!pos)
                {
                    return false;
                }
                data.push_back(static_cast<uint8_t>(pos - kBech32Charset));
            }

            auto values = bech32_hrp_expand(hrp);
            values.insert(values.end(), data.begin(), data.end());
            return bech32_polymod(values) == kBech32mConst;
        }

        std::string strip_hex_prefix(std::string value)
        {
            if (value.rfind("0x", 0) == 0 || value.rfind("0X", 0) == 0)
            {
                return value.substr(2);
            }
            return value;
        }

        std::string extract_submission_payload(const std::string &signed_tx)
        {
            const auto first_non_ws = signed_tx.find_first_not_of(" \t\r\n");
            if (first_non_ws == std::string::npos || signed_tx[first_non_ws] != '{')
            {
                return signed_tx;
            }

            try
            {
                auto envelope = nlohmann::json::parse(signed_tx);
                if (!envelope.is_object())
                {
                    return signed_tx;
                }

                if (envelope.contains("signedPayload") && envelope["signedPayload"].is_string())
                {
                    const std::string payload = envelope["signedPayload"].get<std::string>();
                    if (!payload.empty())
                    {
                        return payload;
                    }
                }

                if (envelope.contains("payload") && envelope["payload"].is_string())
                {
                    const std::string payload = envelope["payload"].get<std::string>();
                    if (!payload.empty())
                    {
                        return payload;
                    }
                }

                if (envelope.contains("transaction") && envelope["transaction"].is_string() &&
                    envelope.contains("signature") && envelope["signature"].is_string())
                {
                    const std::string tx = envelope["transaction"].get<std::string>();
                    const std::string sig = strip_hex_prefix(envelope["signature"].get<std::string>());
                    if (!tx.empty() && !sig.empty())
                    {
                        return tx + sig;
                    }
                }
            }
            catch (...)
            {
                return signed_tx;
            }

            return signed_tx;
        }
    } // namespace

    MidnightBlockchain::MidnightBlockchain() : connected_(false) {}

    MidnightBlockchain::~MidnightBlockchain()
    {
        if (connected_)
        {
            disconnect();
        }
    }

    void MidnightBlockchain::initialize(const std::string &network, const ProtocolParams &protocol_params)
    {
        network_ = network;
        protocol_params_ = protocol_params;

        std::ostringstream msg;
        msg << "Midnight blockchain manager initialized for network: " << network
            << " with min_fee_a: " << protocol_params.min_fee_a;
        midnight::g_logger->info(msg.str());
    }

    bool MidnightBlockchain::connect(const std::string &node_url)
    {
        node_url_ = node_url;

        std::ostringstream msg;
        msg << "Connecting to Midnight node at: " << node_url;
        midnight::g_logger->info(msg.str());

        try
        {
            // Create RPC client for node communication
            rpc_ = std::make_unique<midnight::network::MidnightNodeRPC>(node_url, protocol_params_.rpc_timeout_ms);

            // Verify node is ready
            if (!rpc_->is_ready())
            {
                midnight::g_logger->warn("Node is not ready yet");
                connected_ = false;
                return false;
            }

            // Fetch protocol parameters from node if not initialized
            if (protocol_params_.min_fee_a == 0)
            {
                protocol_params_ = rpc_->get_protocol_params();
                msg.str("");
                msg << "Fetched protocol params: min_fee_a=" << protocol_params_.min_fee_a;
                midnight::g_logger->info(msg.str());
            }

            connected_ = true;
            midnight::g_logger->info("Successfully connected to Midnight node");
            return true;
        }
        catch (const std::exception &e)
        {
            msg.str("");
            msg << "Failed to connect to node: " << e.what();
            midnight::g_logger->error(msg.str());
            connected_ = false;
            return false;
        }
    }

    std::string MidnightBlockchain::create_address(const std::string &public_key, uint8_t network_id)
    {
        if (public_key.empty())
        {
            return "";
        }

        std::array<uint8_t, 32> payload{};
        if (!hex_to_bytes32(public_key, payload))
        {
            midnight::g_logger->warn("Invalid public key hex when creating Midnight address");
            return "";
        }

        const std::string hrp = (network_id == 0) ? "mn_addr_preprod" : "mn_addr_mainnet";
        return bech32m_encode(hrp, payload);
    }

    bool MidnightBlockchain::validate_address(const std::string &address)
    {
        return bech32m_validate_address(address);
    }

    Result MidnightBlockchain::build_transaction(
        const std::vector<UTXO> &utxos,
        const std::vector<std::pair<std::string, uint64_t>> &outputs,
        const std::string &change_address)
    {

        Result result{false, "", ""};
        if (utxos.empty())
        {
            result.error_message = "No UTXOs provided";
            return result;
        }

        if (outputs.empty())
        {
            result.error_message = "No outputs specified";
            return result;
        }

        midnight::g_logger->debug("Building Midnight transaction (native CBOR)");

        // 1. Calculate total input value from UTXOs
        uint64_t total_input = 0;
        for (const auto &utxo : utxos)
        {
            total_input += utxo.amount;
        }

        // 2. Calculate total output value
        uint64_t total_output = 0;
        for (const auto &output : outputs)
        {
            total_output += output.second;
        }

        // 3. Build Transaction object with real inputs and outputs
        Transaction tx;

        for (const auto &utxo : utxos)
        {
            Transaction::Input input;
            input.tx_hash = utxo.tx_hash;
            input.output_index = utxo.output_index;
            tx.add_input(input);
        }

        for (const auto &[addr, amt] : outputs)
        {
            Transaction::Output output;
            output.address = addr;
            output.amount = amt;
            tx.add_output(output);
        }

        // 4. Iterative fee estimation (two-pass for accuracy)
        //    First pass: estimate with preliminary size
        uint64_t fee = calculate_min_fee(tx.get_size());

        if (total_input < total_output + fee)
        {
            result.error_message = "Insufficient funds for transaction and fees";
            return result;
        }

        // 5. Calculate and add change output
        uint64_t change = total_input - total_output - fee;
        if (change > 0)
        {
            Transaction::Output change_output;
            change_output.address = change_address;
            change_output.amount = change;
            tx.add_output(change_output);
        }

        // 6. Set validity interval from chain tip
        if (connected_ && rpc_)
        {
            try
            {
                auto tip = rpc_->get_chain_tip();
                // TTL = current slot + 200 slots (~400 seconds on Midnight)
                tx.set_validity(tip.first + 200, 0);
            }
            catch (const std::exception &e)
            {
                midnight::g_logger->debug(
                    std::string("Could not fetch chain tip for TTL, using fallback: ") + e.what());
                tx.set_validity(999999999, 0);
            }
        }
        else
        {
            tx.set_validity(999999999, 0);
        }

        // 7. Second-pass fee with final transaction size (including change output)
        uint64_t final_fee = calculate_min_fee(tx.get_size());
        if (final_fee > fee)
        {
            // Fee increased due to larger tx; adjust change if possible
            uint64_t fee_diff = final_fee - fee;
            if (change >= fee_diff)
            {
                change -= fee_diff;
                fee = final_fee;
                // Update the last output (change) with adjusted amount
                if (change > 0)
                {
                    // Rebuild the transaction with adjusted change
                    Transaction tx_final;
                    for (const auto &input : tx.get_inputs())
                    {
                        tx_final.add_input(input);
                    }

                    const auto &orig_outputs = tx.get_outputs();
                    for (size_t i = 0; i + 1 < orig_outputs.size(); ++i)
                    {
                        tx_final.add_output(orig_outputs[i]);
                    }

                    Transaction::Output adjusted_change;
                    adjusted_change.address = change_address;
                    adjusted_change.amount = change;
                    tx_final.add_output(adjusted_change);

                    tx_final.set_validity(tx.get_size() > 0 ? 999999999 : 0, 0);
                    // Preserve the validity from the original tx
                    if (connected_ && rpc_)
                    {
                        try
                        {
                            auto tip = rpc_->get_chain_tip();
                            tx_final.set_validity(tip.first + 200, 0);
                        }
                        catch (...)
                        {
                            tx_final.set_validity(999999999, 0);
                        }
                    }
                    else
                    {
                        tx_final.set_validity(999999999, 0);
                    }

                    tx_final.set_fee(fee);

                    result.success = true;
                    result.result = tx_final.to_cbor_hex();

                    std::ostringstream build_msg;
                    build_msg << "Transaction built (CBOR): "
                              << tx_final.get_inputs().size() << " inputs, "
                              << tx_final.get_outputs().size() << " outputs, "
                              << "fee=" << fee << ", change=" << change
                              << ", size=" << tx_final.get_size() << " bytes";
                    midnight::g_logger->info(build_msg.str());

                    return result;
                }
            }
            else
            {
                result.error_message = "Insufficient funds after fee recalculation";
                return result;
            }
        }

        // 8. Set fee and serialize to CBOR hex
        tx.set_fee(fee);

        result.success = true;
        result.result = tx.to_cbor_hex();

        std::ostringstream build_msg;
        build_msg << "Transaction built (CBOR): "
                  << tx.get_inputs().size() << " inputs, "
                  << tx.get_outputs().size() << " outputs, "
                  << "fee=" << fee << ", change=" << change
                  << ", size=" << tx.get_size() << " bytes";
        midnight::g_logger->info(build_msg.str());

        return result;
    }

    Result MidnightBlockchain::sign_transaction(const std::string &transaction_hex, const std::string &private_key)
    {
        Result result{false, "", ""};

        if (transaction_hex.empty() || private_key.empty())
        {
            result.error_message = "Transaction or private key is empty";
            midnight::g_logger->error(result.error_message);
            return result;
        }

        try
        {
            midnight::g_logger->info("Signing transaction with Ed25519...");

            // Initialize crypto library (idempotent - safe to call multiple times)
            midnight::crypto::Ed25519Signer::initialize();

            // Parse private key from hex string
            midnight::crypto::Ed25519Signer::PrivateKey priv_key_bytes{};
            if (!hex_to_fixed_bytes(private_key, priv_key_bytes.data(), priv_key_bytes.size()))
            {
                result.error_message = "Private key must be exactly 128 hex characters (64 bytes), optional 0x prefix";
                midnight::g_logger->error(result.error_message);
                return result;
            }

            // Sign the transaction (transaction_hex is treated as the message)
            auto signature = midnight::crypto::Ed25519Signer::sign_message(
                transaction_hex,
                priv_key_bytes);

            // Convert signature to hex string
            std::string signature_hex = midnight::crypto::Ed25519Signer::signature_to_hex(signature);
            const auto public_key = midnight::crypto::Ed25519Signer::extract_public_key(priv_key_bytes);

            const std::string signed_payload = transaction_hex + signature_hex;
            nlohmann::json envelope = {
                {"format", "midnight-signed-v1"},
                {"algorithm", "ed25519"},
                {"transaction", transaction_hex},
                {"signature", "0x" + signature_hex},
                {"publicKey", "0x" + midnight::crypto::Ed25519Signer::public_key_to_hex(public_key)},
                {"signedPayload", signed_payload},
            };

            // Construct structured output while keeping canonical payload available for submission.
            result.success = true;
            result.result = envelope.dump();

            midnight::g_logger->info("Transaction signed successfully");
            midnight::g_logger->debug("Signature length: " + std::to_string(signature_hex.length()) + " hex chars");

            return result;
        }
        catch (const std::exception &e)
        {
            result.success = false;
            result.error_message = std::string("Signing failed: ") + e.what();
            midnight::g_logger->error(result.error_message);
            return result;
        }
    }

    Result MidnightBlockchain::submit_transaction(const std::string &signed_tx)
    {
        Result result{false, "", ""};

        if (!connected_ || !rpc_)
        {
            result.error_message = "Not connected to Midnight network";
            return result;
        }

        if (signed_tx.empty())
        {
            result.error_message = "Transaction is empty";
            return result;
        }

        midnight::g_logger->info("Submitting transaction to Midnight network");
        const std::string submission_payload = extract_submission_payload(signed_tx);

        try
        {
            // Submit via RPC node
            std::string tx_id = rpc_->submit_transaction(submission_payload);

            result.success = true;
            result.result = tx_id;

            std::ostringstream msg;
            msg << "Transaction submitted: " << tx_id.substr(0, 16) << "...";
            midnight::g_logger->info(msg.str());
        }
        catch (const std::exception &e)
        {
            result.success = false;
            result.error_message = std::string("RPC submission failed: ") + e.what();

            std::ostringstream msg;
            msg << "Failed to submit transaction: " << e.what();
            midnight::g_logger->error(msg.str());
        }

        return result;
    }

    std::vector<UTXO> MidnightBlockchain::query_utxos(const std::string &address)
    {
        std::vector<UTXO> utxos;

        if (!connected_ || !rpc_)
        {
            midnight::g_logger->warn("Not connected to query UTXOs");
            return utxos;
        }

        std::ostringstream msg;
        msg << "Querying UTXOs for address: " << address.substr(0, 20) << "...";
        midnight::g_logger->debug(msg.str());

        try
        {
            // Query from RPC node
            utxos = rpc_->get_utxos(address);

            msg.str("");
            msg << "Found " << utxos.size() << " UTXOs";
            midnight::g_logger->debug(msg.str());
        }
        catch (const std::exception &e)
        {
            msg.str("");
            msg << "Failed to query UTXOs: " << e.what();
            midnight::g_logger->error(msg.str());
        }

        return utxos;
    }

    ProtocolParams MidnightBlockchain::get_protocol_params() const
    {
        return protocol_params_;
    }

    Result MidnightBlockchain::get_chain_tip() const
    {
        Result result{false, "", ""};

        if (!connected_ || !rpc_)
        {
            result.error_message = "Not connected to Midnight network";
            return result;
        }

        try
        {
            auto tip = rpc_->get_chain_tip();
            result.success = true;
            result.result = "{\"height\":" + std::to_string(tip.first) +
                            ",\"hash\":\"" + tip.second + "\"}";
        }
        catch (const std::exception &e)
        {
            result.success = false;
            result.error_message = std::string("Failed to query chain tip: ") + e.what();
        }

        return result;
    }

    void MidnightBlockchain::disconnect()
    {
        connected_ = false;
        rpc_ = nullptr; // Clean up RPC client
        midnight::g_logger->info("Disconnected from Midnight network");
    }

    uint64_t MidnightBlockchain::calculate_min_fee(size_t tx_size)
    {
        // Fee formula: fee = minFeeA * size + minFeeB
        return protocol_params_.min_fee_a * tx_size + protocol_params_.min_fee_b;
    }

    bool MidnightBlockchain::validate_transaction(const Transaction &tx)
    {
        // Validate transaction structure
        return !tx.get_inputs().empty() && !tx.get_outputs().empty();
    }

} // namespace midnight::blockchain

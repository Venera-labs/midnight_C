#include "midnight/blockchain/transaction.hpp"
#include "midnight/core/logger.hpp"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <numeric>
#include <iomanip>
#include <array>
#include <stdexcept>

#if defined(MIDNIGHT_ENABLE_OPENSSL_CRYPTO) && MIDNIGHT_ENABLE_OPENSSL_CRYPTO
#include <openssl/sha.h>
#define MIDNIGHT_HAS_OPENSSL_CRYPTO 1
#else
#define MIDNIGHT_HAS_OPENSSL_CRYPTO 0
#endif

namespace midnight::blockchain
{
    namespace
    {
        std::string bytes_to_hex(const std::vector<uint8_t> &bytes)
        {
            std::ostringstream out;
            out << std::hex << std::setfill('0');
            for (uint8_t byte : bytes)
            {
                out << std::setw(2) << static_cast<int>(byte);
            }
            return out.str();
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

        std::vector<uint8_t> hex_to_bytes(std::string hex)
        {
            if (hex.rfind("0x", 0) == 0 || hex.rfind("0X", 0) == 0)
            {
                hex = hex.substr(2);
            }

            if (hex.empty() || (hex.size() % 2) != 0)
            {
                throw std::invalid_argument("CBOR hex payload must contain an even number of characters");
            }

            std::vector<uint8_t> out;
            out.reserve(hex.size() / 2);

            for (size_t i = 0; i < hex.size(); i += 2)
            {
                const int hi = hex_nibble(hex[i]);
                const int lo = hex_nibble(hex[i + 1]);
                if (hi < 0 || lo < 0)
                {
                    throw std::invalid_argument("CBOR hex payload contains non-hex characters");
                }

                out.push_back(static_cast<uint8_t>((hi << 4) | lo));
            }

            return out;
        }

        Transaction::Certificate certificate_from_json(const nlohmann::json &json_cert)
        {
            Transaction::Certificate cert{};
            const int raw_type = json_cert.value("type", 0);
            const int clamped_type = std::max(0, std::min(2, raw_type));
            cert.type = static_cast<Transaction::Certificate::Type>(clamped_type);
            cert.stake_key_hash = json_cert.value("stakeKeyHash", "");
            cert.pool_id = json_cert.value("poolId", "");
            return cert;
        }

#if !MIDNIGHT_HAS_OPENSSL_CRYPTO
        std::array<uint8_t, 32> deterministic_fallback_digest(const std::vector<uint8_t> &payload)
        {
            constexpr uint64_t kOffsetBasis = 1469598103934665603ULL;
            constexpr uint64_t kPrime = 1099511628211ULL;

            std::array<uint8_t, 32> digest{};
            for (size_t block = 0; block < 4; ++block)
            {
                uint64_t state = kOffsetBasis ^ (0x9E3779B97F4A7C15ULL * static_cast<uint64_t>(block + 1));
                for (uint8_t byte : payload)
                {
                    state ^= static_cast<uint64_t>(byte + static_cast<uint8_t>(block));
                    state *= kPrime;
                    state ^= (state >> 32);
                }

                for (size_t i = 0; i < 8; ++i)
                {
                    digest[(block * 8) + i] = static_cast<uint8_t>((state >> (i * 8)) & 0xFF);
                }
            }

            return digest;
        }
#endif

        std::string sha256_hex(const std::vector<uint8_t> &payload)
        {
#if MIDNIGHT_HAS_OPENSSL_CRYPTO
            std::array<uint8_t, SHA256_DIGEST_LENGTH> digest{};
            SHA256(payload.data(), payload.size(), digest.data());
            return bytes_to_hex(std::vector<uint8_t>(digest.begin(), digest.end()));
#else
            const auto digest = deterministic_fallback_digest(payload);
            return bytes_to_hex(std::vector<uint8_t>(digest.begin(), digest.end()));
#endif
        }
    } // namespace

    Transaction::Transaction(const std::string &tx_id) : tx_id_(tx_id)
    {
        if (tx_id.empty())
        {
            tx_id_ = "tx_" + std::to_string(reinterpret_cast<uintptr_t>(this));
        }
    }

    void Transaction::add_input(const Input &input)
    {
        inputs_.push_back(input);
        std::ostringstream msg;
        msg << "Added input: " << input.tx_hash.substr(0, 16) << "...#" << input.output_index;
        midnight::g_logger->debug(msg.str());
    }

    void Transaction::add_output(const Output &output)
    {
        outputs_.push_back(output);
        std::ostringstream msg;
        msg << "Added output: " << output.address.substr(0, 30) << "... ("
            << output.amount << " lovelace)";
        midnight::g_logger->debug(msg.str());
    }

    void Transaction::add_certificate(const Certificate &cert)
    {
        certificates_.push_back(cert);
        std::ostringstream msg;
        msg << "Added certificate type: " << static_cast<int>(cert.type);
        midnight::g_logger->debug(msg.str());
    }

    void Transaction::set_validity(uint64_t invalid_hereafter, uint64_t invalid_before)
    {
        invalid_hereafter_ = invalid_hereafter;
        invalid_before_ = invalid_before;

        std::ostringstream msg;
        msg << "Set validity: " << invalid_before << " to " << invalid_hereafter;
        midnight::g_logger->debug(msg.str());
    }

    void Transaction::set_fee(uint64_t fee)
    {
        fee_ = fee;

        std::ostringstream msg;
        msg << "Set fee: " << fee << " basic units";
        midnight::g_logger->debug(msg.str());
    }

    std::string Transaction::calculate_hash() const
    {
        // Hash the canonical transaction body (excluding mutable/display tx_id).
        nlohmann::json body = nlohmann::json::object();
        body["encoding"] = "midnight-tx-v1";
        body["invalidBefore"] = invalid_before_;
        body["invalidHereafter"] = invalid_hereafter_;
        body["fee"] = fee_;

        nlohmann::json inputs = nlohmann::json::array();
        for (const auto &input : inputs_)
        {
            inputs.push_back({
                {"txHash", input.tx_hash},
                {"outputIndex", input.output_index},
            });
        }
        body["inputs"] = std::move(inputs);

        nlohmann::json outputs = nlohmann::json::array();
        for (const auto &output : outputs_)
        {
            nlohmann::json assets = nlohmann::json::object();
            for (const auto &[policy_id, policy_assets] : output.assets)
            {
                nlohmann::json asset_map = nlohmann::json::object();
                for (const auto &[asset_name, quantity] : policy_assets)
                {
                    asset_map[asset_name] = quantity;
                }
                assets[policy_id] = std::move(asset_map);
            }

            outputs.push_back({
                {"address", output.address},
                {"amount", output.amount},
                {"assets", std::move(assets)},
            });
        }
        body["outputs"] = std::move(outputs);

        nlohmann::json certs = nlohmann::json::array();
        for (const auto &cert : certificates_)
        {
            certs.push_back({
                {"type", static_cast<int>(cert.type)},
                {"stakeKeyHash", cert.stake_key_hash},
                {"poolId", cert.pool_id},
            });
        }
        body["certificates"] = std::move(certs);

        const auto cbor = nlohmann::json::to_cbor(body);
        return sha256_hex(cbor);
    }

    uint64_t Transaction::get_total_inputs() const
    {
        if (inputs_.empty())
        {
            return 0;
        }

        // Inputs do not carry explicit amounts in this representation.
        // Return the minimum required input value implied by outputs + fee.
        return get_total_outputs() + calculate_min_fee();
    }

    uint64_t Transaction::get_total_outputs() const
    {
        return std::accumulate(outputs_.begin(), outputs_.end(), static_cast<uint64_t>(0),
                               [](uint64_t sum, const Output &output)
                               { return sum + output.amount; });
    }

    std::string Transaction::to_cbor_hex() const
    {
        nlohmann::json tx_json = nlohmann::json::object();
        tx_json["encoding"] = "midnight-tx-v1";
        tx_json["txId"] = tx_id_;
        tx_json["fee"] = fee_;
        tx_json["invalidBefore"] = invalid_before_;
        tx_json["invalidHereafter"] = invalid_hereafter_;

        nlohmann::json inputs = nlohmann::json::array();
        for (const auto &input : inputs_)
        {
            inputs.push_back({
                {"txHash", input.tx_hash},
                {"outputIndex", input.output_index},
            });
        }
        tx_json["inputs"] = std::move(inputs);

        nlohmann::json outputs = nlohmann::json::array();
        for (const auto &output : outputs_)
        {
            nlohmann::json assets = nlohmann::json::object();
            for (const auto &[policy_id, policy_assets] : output.assets)
            {
                nlohmann::json asset_map = nlohmann::json::object();
                for (const auto &[asset_name, quantity] : policy_assets)
                {
                    asset_map[asset_name] = quantity;
                }
                assets[policy_id] = std::move(asset_map);
            }

            outputs.push_back({
                {"address", output.address},
                {"amount", output.amount},
                {"assets", std::move(assets)},
            });
        }
        tx_json["outputs"] = std::move(outputs);

        nlohmann::json certs = nlohmann::json::array();
        for (const auto &cert : certificates_)
        {
            certs.push_back({
                {"type", static_cast<int>(cert.type)},
                {"stakeKeyHash", cert.stake_key_hash},
                {"poolId", cert.pool_id},
            });
        }
        tx_json["certificates"] = std::move(certs);

        const auto cbor = nlohmann::json::to_cbor(tx_json);
        return bytes_to_hex(cbor);
    }

    std::string Transaction::to_json() const
    {
        // CIP-116 JSON serialization format
        std::ostringstream json;
        json << "{"
             << "\"type\": \"Tx\","
             << "\"description\": \"Transaction\","
             << "\"cborHex\": \"" << to_cbor_hex() << "\""
             << "}";

        return json.str();
    }

    size_t Transaction::get_size() const
    {
        const std::string hex = to_cbor_hex();
        return hex.size() / 2;
    }

    Transaction Transaction::from_cbor_hex(const std::string &cbor_hex)
    {
        const auto bytes = hex_to_bytes(cbor_hex);
        const auto tx_json = nlohmann::json::from_cbor(bytes, true, true);
        if (tx_json.is_discarded() || !tx_json.is_object())
        {
            throw std::invalid_argument("Invalid CBOR transaction payload");
        }

        Transaction tx(tx_json.value("txId", ""));
        tx.invalid_before_ = tx_json.value("invalidBefore", 0ULL);
        tx.invalid_hereafter_ = tx_json.value("invalidHereafter", 0ULL);
        tx.fee_ = tx_json.value("fee", 0ULL);

        if (tx_json.contains("inputs") && tx_json["inputs"].is_array())
        {
            for (const auto &json_input : tx_json["inputs"])
            {
                Input input{};
                input.tx_hash = json_input.value("txHash", "");
                input.output_index = json_input.value("outputIndex", 0U);
                tx.inputs_.push_back(std::move(input));
            }
        }

        if (tx_json.contains("outputs") && tx_json["outputs"].is_array())
        {
            for (const auto &json_output : tx_json["outputs"])
            {
                Output output{};
                output.address = json_output.value("address", "");
                output.amount = json_output.value("amount", 0ULL);

                if (json_output.contains("assets") && json_output["assets"].is_object())
                {
                    for (auto it = json_output["assets"].begin(); it != json_output["assets"].end(); ++it)
                    {
                        std::map<std::string, uint64_t> asset_map;
                        if (it.value().is_object())
                        {
                            for (auto ait = it.value().begin(); ait != it.value().end(); ++ait)
                            {
                                asset_map[ait.key()] = ait.value().get<uint64_t>();
                            }
                        }
                        output.assets[it.key()] = std::move(asset_map);
                    }
                }

                tx.outputs_.push_back(std::move(output));
            }
        }

        if (tx_json.contains("certificates") && tx_json["certificates"].is_array())
        {
            for (const auto &json_cert : tx_json["certificates"])
            {
                tx.certificates_.push_back(certificate_from_json(json_cert));
            }
        }

        midnight::g_logger->debug("Deserialized transaction from CBOR payload");
        return tx;
    }

    // Helper for fee calculation (simplified)
    uint64_t Transaction::calculate_min_fee() const
    {
        // Cardano fee formula: fee = minFeeA * size + minFeeB
        // Using defaults: minFeeA = 44, minFeeB = 155381
        const uint64_t MIN_FEE_A = 44;
        const uint64_t MIN_FEE_B = 155381;

        return MIN_FEE_A * get_size() + MIN_FEE_B;
    }

} // namespace midnight::blockchain

#include "midnight/blockchain/native_wallet_ops.hpp"
#include "midnight/blockchain/transaction.hpp"
#include "midnight/crypto/ed25519_signer.hpp"
#include "midnight/core/logger.hpp"
#include <sstream>
#include <numeric>
#include <iomanip>
#include <cctype>

namespace midnight::blockchain
{

    namespace
    {
        std::string bytes_to_hex_native(const uint8_t *data, size_t len)
        {
            std::ostringstream out;
            out << std::hex << std::setfill('0');
            for (size_t i = 0; i < len; ++i)
            {
                out << std::setw(2) << static_cast<int>(data[i]);
            }
            return out.str();
        }

        bool hex_to_bytes_native(const std::string &hex_input, uint8_t *out, size_t out_size)
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
                char hi = hex[i * 2];
                char lo = hex[i * 2 + 1];

                auto nibble = [](char c) -> int
                {
                    if (c >= '0' && c <= '9')
                        return c - '0';
                    char lower = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                    if (lower >= 'a' && lower <= 'f')
                        return 10 + (lower - 'a');
                    return -1;
                };

                int h = nibble(hi);
                int l = nibble(lo);
                if (h < 0 || l < 0)
                {
                    return false;
                }
                out[i] = static_cast<uint8_t>((h << 4) | l);
            }

            return true;
        }
    } // namespace

    NativeTransferResult transfer_night_native(
        MidnightBlockchain &blockchain,
        const std::string &private_key_hex,
        const std::string &to_address,
        uint64_t amount)
    {
        NativeTransferResult result;
        result.destination_address = to_address;
        result.amount = std::to_string(amount);

        // Validate connection
        if (!blockchain.is_connected())
        {
            result.error = "Not connected to Midnight network";
            return result;
        }

        // Validate destination address
        if (!MidnightBlockchain::validate_address(to_address))
        {
            result.error = "Invalid destination address format";
            return result;
        }

        // Validate private key
        if (private_key_hex.empty())
        {
            result.error = "Private key is required";
            return result;
        }

        midnight::g_logger->info("Starting native tNIGHT transfer (no Node.js bridge)");

        try
        {
            // 1. Initialize crypto library
            midnight::crypto::Ed25519Signer::initialize();

            // 2. Parse private key and derive public key / address
            midnight::crypto::Ed25519Signer::PrivateKey priv_key_bytes{};
            if (!hex_to_bytes_native(private_key_hex, priv_key_bytes.data(), priv_key_bytes.size()))
            {
                result.error = "Private key must be exactly 128 hex characters (64 bytes), optional 0x prefix";
                return result;
            }

            auto pub_key = midnight::crypto::Ed25519Signer::extract_public_key(priv_key_bytes);
            std::string pub_key_hex = bytes_to_hex_native(pub_key.data(), pub_key.size());
            std::string source_address = blockchain.create_address(pub_key_hex);

            if (source_address.empty())
            {
                result.error = "Failed to derive address from private key";
                return result;
            }

            result.source_address = source_address;

            std::ostringstream msg;
            msg << "Source address: " << source_address.substr(0, 30) << "...";
            midnight::g_logger->info(msg.str());

            // 3. Query UTXOs for the source address
            auto utxos = blockchain.query_utxos(source_address);
            if (utxos.empty())
            {
                result.error = "No UTXOs found at source address";
                return result;
            }

            // Calculate available balance
            uint64_t total_balance = 0;
            for (const auto &utxo : utxos)
            {
                total_balance += utxo.amount;
            }
            result.balance_before = total_balance;

            msg.str("");
            msg << "Found " << utxos.size() << " UTXOs with total balance: " << total_balance;
            midnight::g_logger->info(msg.str());

            if (total_balance < amount)
            {
                result.error = "Insufficient balance: have " + std::to_string(total_balance) +
                               ", need " + std::to_string(amount);
                return result;
            }

            // 4. Build the transaction (now produces real CBOR!)
            std::vector<std::pair<std::string, uint64_t>> outputs = {{to_address, amount}};
            auto build_result = blockchain.build_transaction(utxos, outputs, source_address);

            if (!build_result.success)
            {
                result.error = "Transaction build failed: " + build_result.error_message;
                return result;
            }

            midnight::g_logger->info("Transaction built successfully, signing...");

            // 5. Sign the transaction
            auto sign_result = blockchain.sign_transaction(build_result.result, private_key_hex);
            if (!sign_result.success)
            {
                result.error = "Transaction signing failed: " + sign_result.error_message;
                return result;
            }

            midnight::g_logger->info("Transaction signed, submitting to network...");

            // 6. Submit the signed transaction
            auto submit_result = blockchain.submit_transaction(sign_result.result);
            if (!submit_result.success)
            {
                result.error = "Transaction submission failed: " + submit_result.error_message;
                return result;
            }

            result.success = true;
            result.txid = submit_result.result;

            msg.str("");
            msg << "Native transfer complete! txid=" << result.txid.substr(0, 16) << "...";
            midnight::g_logger->info(msg.str());

            return result;
        }
        catch (const std::exception &e)
        {
            result.error = std::string("Native transfer failed: ") + e.what();
            midnight::g_logger->error(result.error);
            return result;
        }
    }

    NativeWalletStateResult query_wallet_state_native(
        MidnightBlockchain &blockchain,
        const std::string &address)
    {
        NativeWalletStateResult result;
        result.address = address;

        // Validate connection
        if (!blockchain.is_connected())
        {
            result.error = "Not connected to Midnight network";
            return result;
        }

        // Validate address format
        if (!MidnightBlockchain::validate_address(address))
        {
            result.error = "Invalid address format";
            return result;
        }

        midnight::g_logger->info("Querying native wallet state (no Node.js bridge)");

        try
        {
            // Query UTXOs for the address
            auto utxos = blockchain.query_utxos(address);

            result.utxo_count = utxos.size();

            // Sum up the total unshielded balance
            result.unshielded_balance = std::accumulate(
                utxos.begin(), utxos.end(), static_cast<uint64_t>(0),
                [](uint64_t sum, const UTXO &utxo)
                {
                    return sum + utxo.amount;
                });

            result.success = true;

            std::ostringstream msg;
            msg << "Wallet state: address=" << address.substr(0, 30) << "..."
                << " balance=" << result.unshielded_balance
                << " utxos=" << result.utxo_count;
            midnight::g_logger->info(msg.str());

            return result;
        }
        catch (const std::exception &e)
        {
            result.error = std::string("Wallet state query failed: ") + e.what();
            midnight::g_logger->error(result.error);
            return result;
        }
    }

} // namespace midnight::blockchain

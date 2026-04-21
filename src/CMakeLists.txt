# Core library source files

set(MIDNIGHT_CORE_SOURCES
    core/config.cpp
    core/logger.cpp
    session/session_manager.cpp
)

set(MIDNIGHT_PROTOCOL_SOURCES)

# Protocol implementations
if(ENABLE_MQTT)
    list(APPEND MIDNIGHT_PROTOCOL_SOURCES
        protocols/mqtt/mqtt_client.cpp
        protocols/mqtt/mqtt_connection.cpp
    )
endif()

if(ENABLE_COAP)
    list(APPEND MIDNIGHT_PROTOCOL_SOURCES
        protocols/coap/coap_client.cpp
        protocols/coap/coap_message.cpp
    )
endif()

if(ENABLE_HTTP)
    list(APPEND MIDNIGHT_PROTOCOL_SOURCES
        protocols/http/http_client.cpp
        protocols/http/http_request.cpp
    )
endif()

if(ENABLE_WEBSOCKET)
    list(APPEND MIDNIGHT_PROTOCOL_SOURCES
        protocols/websocket/ws_client.cpp
        protocols/websocket/ws_connection.cpp
    )
endif()

set(MIDNIGHT_BLOCKCHAIN_SOURCES)

# Network support
set(MIDNIGHT_NETWORK_SOURCES)
if(ENABLE_BLOCKCHAIN)
    list(APPEND MIDNIGHT_NETWORK_SOURCES
        network/network_client.cpp
        network/midnight_node_rpc.cpp
        network/transaction_confirmation.cpp
    )
endif()

# Crypto support (Ed25519, CBOR, etc.)
set(MIDNIGHT_CRYPTO_SOURCES)
if(ENABLE_BLOCKCHAIN)
    list(APPEND MIDNIGHT_CRYPTO_SOURCES
        crypto/ed25519_signer.cpp
    )
endif()

# Zero-Knowledge Proof support (ZK proofs, circuits, witnesses)
set(MIDNIGHT_ZK_SOURCES)
if(ENABLE_BLOCKCHAIN)
    list(APPEND MIDNIGHT_ZK_SOURCES
        zk/proof_types.cpp
        zk/proof_server_client.cpp
        zk/private_state.cpp
        zk/proof_server_resilient_client.cpp
        zk/ledger_state_sync.cpp
    )
endif()

# Blockchain support
if(ENABLE_BLOCKCHAIN)
    list(APPEND MIDNIGHT_BLOCKCHAIN_SOURCES
        blockchain/chain_manager.cpp
        blockchain/transaction.cpp
        blockchain/block.cpp
        blockchain/wallet.cpp
        blockchain/wallet_manager.cpp
        blockchain/official_sdk_bridge.cpp
        blockchain/midnight_adapter.cpp
        blockchain/native_wallet_ops.cpp
        utxo-transactions/utxo_transactions.cpp
        compact-contracts/compact_contracts.cpp
        zk-proofs/zk_proofs.cpp
        monitoring-finality/monitoring_finality.cpp
        signing-submission/signing_submission.cpp
    )
endif()

# Create library
add_library(midnight-core
    ${MIDNIGHT_CORE_SOURCES}
    ${MIDNIGHT_PROTOCOL_SOURCES}
    ${MIDNIGHT_NETWORK_SOURCES}
    ${MIDNIGHT_CRYPTO_SOURCES}
    ${MIDNIGHT_ZK_SOURCES}
    ${MIDNIGHT_BLOCKCHAIN_SOURCES}
)

if(WIN32 AND BUILD_SHARED_LIBS)
    # Ensure an import library is generated for examples linking against the DLL.
    set_target_properties(midnight-core PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
    target_compile_definitions(midnight-core
        PRIVATE MIDNIGHT_BUILDING_DLL
        INTERFACE MIDNIGHT_USING_DLL
    )
endif()

target_include_directories(midnight-core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${HTTPLIB_SOURCE_DIR}
)

if(DEFINED jsoncpp_SOURCE_DIR)
    target_include_directories(midnight-core PRIVATE "${jsoncpp_SOURCE_DIR}/include")
endif()

# Link dependencies
find_package(OpenSSL QUIET)
find_package(Sodium QUIET)

# Fallback to conda-provided crypto libraries when package config files are unavailable.
if(NOT OPENSSL_FOUND AND DEFINED ENV{CONDA_PREFIX})
    set(_MIDNIGHT_CONDA_LIB_ROOT "$ENV{CONDA_PREFIX}/Library")

    find_path(OPENSSL_INCLUDE_DIR
        NAMES openssl/ssl.h
        PATHS "${_MIDNIGHT_CONDA_LIB_ROOT}/include"
        NO_DEFAULT_PATH
    )
    find_library(OPENSSL_SSL_LIBRARY
        NAMES libssl ssl
        PATHS "${_MIDNIGHT_CONDA_LIB_ROOT}/lib"
        NO_DEFAULT_PATH
    )
    find_library(OPENSSL_CRYPTO_LIBRARY
        NAMES libcrypto crypto
        PATHS "${_MIDNIGHT_CONDA_LIB_ROOT}/lib"
        NO_DEFAULT_PATH
    )

    if(OPENSSL_INCLUDE_DIR AND OPENSSL_SSL_LIBRARY AND OPENSSL_CRYPTO_LIBRARY)
        if(NOT TARGET OpenSSL::SSL)
            add_library(OpenSSL::SSL UNKNOWN IMPORTED)
            set_target_properties(OpenSSL::SSL PROPERTIES
                IMPORTED_LOCATION "${OPENSSL_SSL_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
            )
        endif()

        if(NOT TARGET OpenSSL::Crypto)
            add_library(OpenSSL::Crypto UNKNOWN IMPORTED)
            set_target_properties(OpenSSL::Crypto PROPERTIES
                IMPORTED_LOCATION "${OPENSSL_CRYPTO_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
            )
        endif()

        set(OPENSSL_FOUND TRUE)
        message(STATUS "Using OpenSSL from CONDA_PREFIX: ${_MIDNIGHT_CONDA_LIB_ROOT}")
    endif()
endif()

if(NOT Sodium_FOUND AND DEFINED ENV{CONDA_PREFIX})
    set(_MIDNIGHT_CONDA_LIB_ROOT "$ENV{CONDA_PREFIX}/Library")

    find_path(SODIUM_INCLUDE_DIR
        NAMES sodium.h
        PATHS "${_MIDNIGHT_CONDA_LIB_ROOT}/include"
        NO_DEFAULT_PATH
    )
    find_library(SODIUM_LIBRARY
        NAMES libsodium sodium
        PATHS "${_MIDNIGHT_CONDA_LIB_ROOT}/lib"
        NO_DEFAULT_PATH
    )

    if(SODIUM_INCLUDE_DIR AND SODIUM_LIBRARY)
        if(NOT TARGET Sodium::Sodium)
            add_library(Sodium::Sodium UNKNOWN IMPORTED)
            set_target_properties(Sodium::Sodium PROPERTIES
                IMPORTED_LOCATION "${SODIUM_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}"
            )
        endif()

        set(Sodium_FOUND TRUE)
        message(STATUS "Using libsodium from CONDA_PREFIX: ${_MIDNIGHT_CONDA_LIB_ROOT}")
    endif()
endif()

target_link_libraries(midnight-core
    PUBLIC
        nlohmann_json::nlohmann_json
        fmt::fmt
        $<$<TARGET_EXISTS:jsoncpp_lib>:jsoncpp_lib>
        $<$<TARGET_EXISTS:JsonCpp::JsonCpp>:JsonCpp::JsonCpp>
    PRIVATE
        $<$<BOOL:${OPENSSL_FOUND}>:OpenSSL::SSL>
        $<$<BOOL:${OPENSSL_FOUND}>:OpenSSL::Crypto>
        $<$<BOOL:${Sodium_FOUND}>:Sodium::Sodium>
        $<$<PLATFORM_ID:Windows>:ws2_32>
        $<$<PLATFORM_ID:Windows>:crypt32>
        $<$<PLATFORM_ID:Windows>:secur32>
        $<$<PLATFORM_ID:Windows>:bcrypt>
        $<$<PLATFORM_ID:Windows>:iphlpapi>
)

# macOS frameworks required by cpp-httplib TLS (system certificate loading)
if(APPLE)
    find_library(SECURITY_FRAMEWORK Security)
    find_library(COREFOUNDATION_FRAMEWORK CoreFoundation)
    if(SECURITY_FRAMEWORK AND COREFOUNDATION_FRAMEWORK)
        target_link_libraries(midnight-core PRIVATE
            ${SECURITY_FRAMEWORK}
            ${COREFOUNDATION_FRAMEWORK}
        )
    endif()
endif()

target_compile_definitions(midnight-core
    PRIVATE
        $<$<PLATFORM_ID:Windows>:WIN32_LEAN_AND_MEAN>
        $<$<PLATFORM_ID:Windows>:NOMINMAX>
        $<$<PLATFORM_ID:Windows>:_WIN32_WINNT=0x0A00>
        $<$<PLATFORM_ID:Windows>:WINVER=0x0A00>
        $<$<BOOL:${OPENSSL_FOUND}>:CPPHTTPLIB_OPENSSL_SUPPORT>
        $<$<BOOL:${OPENSSL_FOUND}>:MIDNIGHT_ENABLE_OPENSSL_CRYPTO=1>
        $<$<BOOL:${Sodium_FOUND}>:MIDNIGHT_ENABLE_SODIUM=1>
)

# Set warning levels
if(MSVC)
    target_compile_options(midnight-core PRIVATE /W4)
else()
    target_compile_options(midnight-core PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Set C++ standard
target_compile_features(midnight-core PUBLIC cxx_std_20)

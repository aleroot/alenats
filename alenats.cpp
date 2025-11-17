#include "alenats.h"

#ifdef ASIO_STANDALONE
#include <asio/ip/tcp.hpp>
#include <asio/read.hpp>
#include <asio/read_until.hpp>
#include <asio/write.hpp>
#include <asio/streambuf.hpp>
#include <asio/connect.hpp>
#include <asio/buffer.hpp>
#include <asio/spawn.hpp>
#include <asio/co_spawn.hpp>
#include <asio/awaitable.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#else
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#endif

#include <openssl/evp.h>
#include <openssl/err.h>
#include <array>
#include <span>
#include <print>
#include <sstream>
#include <variant>
#include <queue>
#include <algorithm>
#include <format>
#include <chrono>
#include <stdexcept>
#include <cstdlib>
#include <istream>
#include <unordered_map>
#include <charconv>

#include "simdjson.h"

#ifdef ASIO_STANDALONE
#include <system_error>
namespace asio_system = std;
#else
namespace asio_system = boost::system;
#endif

namespace Nats::Crypto {

// --- OpenSSL Smart Pointers ---
struct EVP_PKEY_deleter { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct EVP_MD_CTX_deleter { void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); } };

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EVP_PKEY_deleter>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_deleter>;


// --- Base64URL Encoding ---
std::string base64_url_encode(std::span<const std::byte> data) {
    constexpr std::string_view TBL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string dest;
    dest.reserve(((data.size() + 2) / 3) * 4);

    for (size_t i = 0; i < data.size(); i += 3) {
        std::uint32_t chunk = (std::uint32_t)data[i] << 16;
        if (i + 1 < data.size()) chunk |= (std::uint32_t)data[i + 1] << 8;
        if (i + 2 < data.size()) chunk |= (std::uint32_t)data[i + 2];

        dest.push_back(TBL[(chunk >> 18) & 0x3F]);
        dest.push_back(TBL[(chunk >> 12) & 0x3F]);

        if (i + 1 < data.size()) {
            dest.push_back(TBL[(chunk >> 6) & 0x3F]);
        }
        if (i + 2 < data.size()) {
            dest.push_back(TBL[chunk & 0x3F]);
        }
    }

    // NATS signatures don't use padding
    return dest;
}

// NKEY Seed Decoding (NKEY seeds are custom Base32-encoded)
constexpr std::array<std::int8_t, 256> BASE32_DECODE_TBL = [] {
    std::array<std::int8_t, 256> tbl;
    tbl.fill(-1);
    constexpr std::string_view chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    for (std::uint8_t i = 0; i < chars.size(); ++i) {
        tbl[static_cast<std::uint8_t>(chars[i])] = i;
    }
    return tbl;
}();

// Decodes the custom Base32 string into a byte vector
std::vector<std::byte> base32_decode(std::string_view encoded) {
    std::vector<std::byte> out;
    out.reserve((encoded.size() * 5) / 8);

    std::uint64_t buffer = 0;
    int bits_left = 0;

    for (const char c : encoded) {
        if (c == '=') break; // Padding
        std::int8_t val = BASE32_DECODE_TBL[static_cast<std::uint8_t>(c)];
        if (val == -1) {
            throw std::runtime_error("Invalid Base32 character in NKEY seed");
        }

        buffer = (buffer << 5) | val;
        bits_left += 5;

        while (bits_left >= 8) {
            bits_left -= 8;
            out.push_back(static_cast<std::byte>((buffer >> bits_left) & 0xFF));
            buffer = buffer & ((1ULL << bits_left) - 1);
        }
    }
    return out;
}

// CRC16-XMODEM implementation for seed validation
std::uint16_t crc16_xmodem(std::span<const std::byte> data) {
    std::uint16_t crc = 0;
    for (const auto b : data) {
        crc ^= static_cast<std::uint16_t>(b) << 8;
        for (int i = 0; i < 8; ++i) {
            crc = (crc & 0x8000) ? (crc << 1) ^ 0x1021 : (crc << 1);
        }
    }
    return crc;
}

// Decodes the full NKEY seed string (e.g., "SU...") into a raw 32-byte private key
std::array<std::byte, 32> decode_nkey_seed(std::string_view seed) {
    if (seed.empty() || seed[0] != 'S') {
        throw std::runtime_error("Invalid NKEY seed: must start with 'S'");
    }

    // The second character indicates the type (User, Account, Operator)
    // We only support User keys, which start with 'SU'
    if (seed.size() < 4 || seed[1] != 'U') {
         throw std::runtime_error("Invalid NKEY seed: not a User seed (must start with 'SU')");
    }

    auto decoded = base32_decode(seed);

    // (2-byte prefix + 32-byte seed + 2-byte checksum)
    if (decoded.size() != 36) {
        throw std::runtime_error(std::format("Invalid NKEY seed: incorrect decoded length ({})", decoded.size()));
    }

    const auto decoded_span = std::span{decoded};

    // The prefix bytes are derived from the NATS spec
    // Per NATS nkeys, Seed prefix is 18 << 3 = 144
    // Per NATS nkeys, User prefix is 20 << 3 = 160
    //
    // The *first* decoded byte is a combination of these:
    // b1 = (SEED_PREFIX & 0xF8) | (USER_PREFIX >> 5)
    // b1 = (144 & 248) | (160 >> 5) = 144 | 5 = 149
    constexpr auto COMBINED_USER_SEED_PREFIX = static_cast<std::byte>(149);

    if (decoded[0] != COMBINED_USER_SEED_PREFIX) {
        throw std::runtime_error(std::format(
            "Invalid NKEY seed: decoded prefix byte is incorrect for a User seed. Expected 149, got {}",
            static_cast<int>(decoded[0])
        ));
    }

    if ((decoded[1] & static_cast<std::byte>(0xF8)) != static_cast<std::byte>(0)) {
         throw std::runtime_error(std::format(
            "Invalid NKEY seed: decoded second byte ({}) is incorrect for a User seed",
            static_cast<int>(decoded[1])
        ));
    }

    auto data_span = decoded_span.subspan(0, 34); // 2-byte prefix + 32-byte seed
    auto checksum_span = decoded_span.subspan(34);

    std::uint16_t expected_crc = (static_cast<std::uint16_t>(checksum_span[0])) |
                                 (static_cast<std::uint16_t>(checksum_span[1]) << 8);
    std::uint16_t actual_crc = crc16_xmodem(data_span);

    if (expected_crc != actual_crc) {
        throw std::runtime_error("Invalid NKEY seed: CRC checksum failed");
    }

    // Extract the 32-byte raw private key (it starts after the 2-byte prefix)
    std::array<std::byte, 32> raw_key;
    std::ranges::copy(decoded_span.subspan(2, 32), raw_key.begin());
    return raw_key;
}

/**
 * Public Signing Function
 * @brief Signs a nonce using a NATS User NKEY Seed (SU...).
 * @param nkey_seed The NKEY seed string (e.g., "SU...").
 * @param nonce The server-provided nonce string to sign.
 * @return A Base64-URL-encoded signature string.
 */
std::string SignWithNKey(std::string_view nkey_seed, std::string_view nonce) {
    auto raw_priv_key = decode_nkey_seed(nkey_seed);
    EvpPkeyPtr pkey(EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519,
        nullptr,
        reinterpret_cast<const unsigned char*>(raw_priv_key.data()),
        raw_priv_key.size()
    ));

    if (!pkey) {
        throw std::runtime_error("OpenSSL: EVP_PKEY_new_raw_private_key failed");
    }

    EvpMdCtxPtr md_ctx(EVP_MD_CTX_new());
    if (!md_ctx) {
        throw std::runtime_error("OpenSSL: EVP_MD_CTX_new failed");
    }

    // Ed25519 is "PureEdDSA" - it signs the message directly, not a digest.
    // We pass NULL for the message digest type.
    if (EVP_DigestSignInit(md_ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1) {
        throw std::runtime_error("OpenSSL: EVP_DigestSignInit failed");
    }

    std::size_t sig_len = 0;
    auto nonce_bytes = std::as_bytes(std::span{nonce});

    if (EVP_DigestSign(md_ctx.get(), nullptr, &sig_len,
                       reinterpret_cast<const unsigned char*>(nonce_bytes.data()),
                       nonce_bytes.size()) != 1) {
        throw std::runtime_error("OpenSSL: EVP_DigestSign (length check) failed");
    }

    std::vector<std::byte> signature(sig_len);

    if (EVP_DigestSign(md_ctx.get(),
                       reinterpret_cast<unsigned char*>(signature.data()), &sig_len,
                       reinterpret_cast<const unsigned char*>(nonce_bytes.data()),
                       nonce_bytes.size()) != 1) {
        throw std::runtime_error("OpenSSL: EVP_DigestSign (signing) failed");
    }
    signature.resize(sig_len);

    return base64_url_encode(signature);
}

} // namespace Nats::Crypto

namespace Nats {

using namespace std::literals;
using tcp = asio::ip::tcp;
using asio_awaitable = asio::awaitable<void, asio::any_io_executor>;
constexpr auto use_awaitable_exec = asio::use_awaitable_t<asio::any_io_executor>{};

struct ConnectionManager::Impl {
    asio::io_context& ioc_;
    ConnectionPool<Nats::Connection> pool_;

    Impl(asio::io_context& ioc) : ioc_(ioc), pool_(ioc) {}
};

namespace Parser {
    const std::string CRLF = "\r\n";

    enum class MsgType { MSG, HMSG, PING, PONG, OK, ERR, INFO, UNKNOWN };

    const std::map<std::string_view, MsgType> message_types_map{
        {"MSG"sv, MsgType::MSG},   {"HMSG"sv, MsgType::HMSG}, {"PING"sv, MsgType::PING},
        {"PONG"sv, MsgType::PONG}, {"+OK"sv, MsgType::OK},    {"-ERR"sv, MsgType::ERR},
        {"INFO"sv, MsgType::INFO},
    };

    struct MsgHeader {
        MsgType type = MsgType::UNKNOWN;
        std::string_view subject;
        std::string_view sid;
        std::optional<std::string_view> reply_to;
        std::size_t header_bytes = 0;
        std::size_t total_bytes = 0;
        std::string_view error_msg;
    };

    std::vector<std::string_view> split_sv(std::string_view str, std::string_view delims = " "sv) {
        std::vector<std::string_view> output;
        size_t start = str.find_first_not_of(delims, 0);
        size_t end = 0;
        while (start != std::string_view::npos) {
            end = str.find_first_of(delims, start);
            if (end == std::string_view::npos) {
                output.emplace_back(str.substr(start));
                break;
            }
            output.emplace_back(str.substr(start, end - start));
            start = str.find_first_not_of(delims, end);
        }
        return output;
    }

    MsgHeader parse_header_line(std::string_view line) {
        if (line.empty()) return {};

        auto p = line.find_first_of(' ');
        std::string_view cmd_sv = (p == std::string_view::npos) ? line : line.substr(0, p);
        std::string_view args_sv = (p == std::string_view::npos) ? ""sv : line.substr(p + 1);

        auto it = message_types_map.find(cmd_sv);
        if (it == message_types_map.end()) {
            return {};
        }

        MsgHeader header;
        header.type = it->second;

        try {
            switch (header.type) {
                case MsgType::MSG: {
                    auto parts = split_sv(args_sv); // {subject} {sid} [reply_to] {n}
                    if (parts.size() < 3 || parts.size() > 4) break;
                    header.subject = parts[0];
                    header.sid = parts[1];
                    std::from_chars(parts.back().data(), parts.back().data() + parts.back().length(), header.total_bytes);
                    if (parts.size() == 4) header.reply_to = parts[2];
                    break;
                }
                case MsgType::HMSG: {
                    auto parts = split_sv(args_sv); // {subject} {sid} [reply_to] {header_n} {total_n}
                    if (parts.size() < 4 || parts.size() > 5) break;
                    header.subject = parts[0];
                    header.sid = parts[1];
                    std::from_chars(parts[parts.size() - 2].data(), parts[parts.size() - 2].data() + parts[parts.size() - 2].length(), header.header_bytes);
                    std::from_chars(parts.back().data(), parts.back().data() + parts.back().length(), header.total_bytes);
                    if (parts.size() == 5) header.reply_to = parts[2];
                    break;
                }
                case MsgType::ERR:
                    header.error_msg = args_sv;
                    break;
                case MsgType::PING:
                case MsgType::PONG:
                case MsgType::OK:
                case MsgType::INFO:
                    break;
                case MsgType::UNKNOWN:
                    break;
            }
        } catch (const std::exception& e) {
            logger.error(std::format("NATS-CLIENT: Failed to parse header '{}': {}", line, e.what()));
            return {};
        }
        return header;
    }
} // namespace Parser

class UnifiedSocket {
    using plain_socket = tcp::socket;
    using ssl_socket = asio::ssl::stream<tcp::socket>;
    std::variant<plain_socket, ssl_socket> socket_;

public:
    using executor_type = asio::any_io_executor;

    UnifiedSocket(asio::io_context& ioc) : socket_(std::in_place_index<0>, ioc) {}
    UnifiedSocket(asio::io_context& ioc, asio::ssl::context& ctx) : socket_(std::in_place_index<1>, ioc, ctx) {}

    executor_type get_executor() {
        if (auto* plain = std::get_if<plain_socket>(&socket_)) {
            return plain->get_executor();
        } else if (auto* ssl = std::get_if<ssl_socket>(&socket_)) {
            return ssl->get_executor();
        } else {
            throw std::runtime_error("Invalid socket state");
        }
    }

    void close() {
        asio_system::error_code ec;
        if (auto* plain = std::get_if<plain_socket>(&socket_)) {
            plain->close(ec);
        } else if (auto* ssl = std::get_if<ssl_socket>(&socket_)) {
            ssl->lowest_layer().close(ec);
        }
    }

    template<typename EndpointRange>
    asio::awaitable<void, asio::any_io_executor> connect_to_range(const EndpointRange& endpoints) {
        if (auto* plain = std::get_if<plain_socket>(&socket_)) {
            co_await asio::async_connect(*plain, endpoints, use_awaitable_exec);
        } else if (auto* ssl = std::get_if<ssl_socket>(&socket_)) {
            co_await asio::async_connect(ssl->lowest_layer(), endpoints, use_awaitable_exec);
        } else {
            throw std::runtime_error("Invalid socket state");
        }
        co_return;
    }

    asio::awaitable<void, asio::any_io_executor> handshake() {
        if (auto* ssl = std::get_if<ssl_socket>(&socket_)) {
            co_await ssl->async_handshake(asio::ssl::stream_base::client, use_awaitable_exec);
        }
        co_return;
    }

    asio::awaitable<std::size_t, asio::any_io_executor> read_until(asio::streambuf& buf, const std::string& delim) {
        if (auto* plain = std::get_if<plain_socket>(&socket_)) {
            co_return co_await asio::async_read_until(*plain, buf, delim, use_awaitable_exec);
        } else if (auto* ssl = std::get_if<ssl_socket>(&socket_)) {
            co_return co_await asio::async_read_until(*ssl, buf, delim, use_awaitable_exec);
        } else {
            throw std::runtime_error("Invalid socket state");
        }
    }

    template<typename CompletionCondition>
    asio::awaitable<std::size_t, asio::any_io_executor> read_exactly(asio::streambuf& buf, CompletionCondition condition) {
        if (auto* plain = std::get_if<plain_socket>(&socket_)) {
            co_return co_await asio::async_read(*plain, buf, condition, use_awaitable_exec);
        } else if (auto* ssl = std::get_if<ssl_socket>(&socket_)) {
            co_return co_await asio::async_read(*ssl, buf, condition, use_awaitable_exec);
        } else {
            throw std::runtime_error("Invalid socket state");
        }
    }

    asio::awaitable<std::size_t, asio::any_io_executor> read_until_raw(asio::streambuf& buf, const std::string& delim) {
        if (auto* plain = std::get_if<plain_socket>(&socket_)) {
            co_return co_await asio::async_read_until(*plain, buf, delim, use_awaitable_exec);
        } else if (auto* ssl = std::get_if<ssl_socket>(&socket_)) {
            co_return co_await asio::async_read_until(ssl->next_layer(), buf, delim, use_awaitable_exec);
        } else {
            throw std::runtime_error("Invalid socket state");
        }
    }

    asio::awaitable<std::size_t, asio::any_io_executor> write(asio::const_buffer buf) {
        if (auto* plain = std::get_if<plain_socket>(&socket_)) {
            co_return co_await asio::async_write(*plain, buf, use_awaitable_exec);
        } else if (auto* ssl = std::get_if<ssl_socket>(&socket_)) {
            co_return co_await asio::async_write(*ssl, buf, use_awaitable_exec);
        } else {
            throw std::runtime_error("Invalid socket state");
        }
    }

    asio::awaitable<std::size_t, asio::any_io_executor> write(const std::vector<asio::const_buffer>& bufs) {
        if (auto* plain = std::get_if<plain_socket>(&socket_)) {
            co_return co_await asio::async_write(*plain, bufs, use_awaitable_exec);
        } else if (auto* ssl = std::get_if<ssl_socket>(&socket_)) {
            co_return co_await asio::async_write(*ssl, bufs, use_awaitable_exec);
        } else {
            throw std::runtime_error("Invalid socket state");
        }
    }
};


/**
 * @class NatsConnection
 * @brief This is the NATS client.
 * It implements the Connection interface directly.
 */
class NatsConnection : public Connection,
                             public std::enable_shared_from_this<NatsConnection> {
public:
    using State = Nats::ClientState;
    using PublishCallback = std::function<void(bool success, std::string_view error)>;

    struct SubscriptionData {
        std::set<std::weak_ptr<Subscription>, std::owner_less<>> endpoints;
        bool active = false;
    };

    struct PendingWrite {
        std::string subject;
        std::map<std::string, std::string> headers;
        Buffer payload;
        PublishCallback callback;
    };

    asio::io_context& ioc_;
    asio::strand<asio::io_context::executor_type> strand_;
    std::atomic<State> state_{State::DISCONNECTED};

    // Connection Config
    std::string host_;
    std::string port_;
    std::optional<Nats::Credentials> auth_;
    bool use_ssl_;
    std::shared_ptr<asio::ssl::context> ssl_ctx_;

    // Connection State
    std::unique_ptr<UnifiedSocket> socket_;
    asio::streambuf read_buf_;
    asio::steady_timer ping_timer_;
    asio::steady_timer connect_timer_;

    // Key: Subject, Value: List of endpoints listening
    std::map<std::string, SubscriptionData> subscriptions_;
    std::queue<PendingWrite> pending_writes_;

    // Re-usable buffer for parsing headers
    std::string header_parse_buffer_;
    std::map<std::string_view, std::string_view> hmsg_header_map_sv_;
    std::map<std::string, std::string> hmsg_header_map_str_; // Backing store
    std::string server_nonce_;
    simdjson::dom::parser json_parser_;

    NatsConnection(asio::io_context& ioc)
        : ioc_(ioc),
          strand_(ioc.get_executor()),
          ping_timer_(ioc),
          connect_timer_(ioc)
    {}

    ~NatsConnection() {
        if (state_.load() != State::STOPPED) {
            ping_timer_.cancel();
            connect_timer_.cancel();
        }
    }

    void start_client(
        std::shared_ptr<NatsConnection> self,
        const std::string& host,
        const std::string& port,
        const std::optional<Nats::Credentials>& auth,
        bool use_ssl
    ) {
        State expected_state = State::DISCONNECTED;
        if (!state_.compare_exchange_strong(expected_state, State::CONNECTING)) {
            return; // Already started
        }

        host_ = host;
        port_ = port;
        auth_ = auth;
        use_ssl_ = use_ssl;

        if (use_ssl_) {
            ssl_ctx_ = std::make_shared<asio::ssl::context>(asio::ssl::context::tlsv12_client);
            ssl_ctx_->set_default_verify_paths();
            ssl_ctx_->set_verify_mode(asio::ssl::verify_peer);
        }

        // Start the main connection loop
        asio::co_spawn(ioc_,
            main_connection_loop(self),
            asio::detached
        );
    }

    asio_awaitable main_connection_loop(std::shared_ptr<NatsConnection> self) {
        co_await asio::post(ioc_.get_executor(), use_awaitable_exec);

        while(state_.load() != State::STOPPED) {
            try {
                state_.store(State::CONNECTING);
                co_await connect_and_run_session(self);
                logger.info("NATS-CLIENT: Disconnected.");
            } catch (const asio_system::system_error& e) {
                // Handle asio-specific errors
                logger.error(std::format("NATS-CLIENT: Connection error({}): {}. Retrying in 5s...", e.code().value(), e.code().message()));
            } catch (const std::exception& e) {
                logger.error(std::format("NATS-CLIENT: General error: {}. Retrying in 5s...", e.what()));
            } catch (...) {
                logger.error("NATS-CLIENT: Unknown connection error. Retrying in 5s...");
            }

            if (state_.load() == State::STOPPED) break;

            state_.store(State::DISCONNECTED);
            ping_timer_.cancel();
            socket_.reset();

            co_await asio::post(strand_, use_awaitable_exec);
            fail_all_pending_writes("Disconnected");

            connect_timer_.expires_after(std::chrono::seconds(5));
            co_await connect_timer_.async_wait(use_awaitable_exec);
        }
    }

    asio_awaitable connect_and_run_session(std::shared_ptr<NatsConnection> self) {
        tcp::resolver resolver(ioc_);
        auto endpoints = co_await resolver.async_resolve(host_, port_, tcp::resolver::flags::address_configured, use_awaitable_exec);

        if (use_ssl_) {
            socket_ = std::make_unique<UnifiedSocket>(ioc_, *ssl_ctx_);
        } else {
            socket_ = std::make_unique<UnifiedSocket>(ioc_);
        }

        co_await socket_->connect_to_range(endpoints);

        logger.info("NATS-CLIENT: TCP connection established, waiting for INFO...");

        // Read the INFO message from server
        // Important: For SSL connections, INFO comes BEFORE TLS handshake (sent in plaintext)
        // For non-SSL, INFO is just regular data
        auto bytes_read_info = use_ssl_
            ? co_await socket_->read_until_raw(read_buf_, Parser::CRLF)
            : co_await socket_->read_until(read_buf_, Parser::CRLF);

        logger.info(std::format("NATS-CLIENT: Read {} bytes for INFO, buffer size now: {}", bytes_read_info, read_buf_.size()));

        // Extract the line from buffer
        std::string info_line;
        {
            std::istream is(&read_buf_);
            std::getline(is, info_line);
        }

        logger.info(std::format("NATS-CLIENT: Raw INFO line: [{}] (len={})", info_line, info_line.length()));

        if (!info_line.empty() && info_line.back() == '\r') {
            info_line.pop_back();
            logger.info(std::format("NATS-CLIENT: After trim: [{}]", info_line));
        }

        if (info_line.empty()) {
            throw std::runtime_error("INFO line is empty");
        }

        if (!info_line.starts_with("INFO ")) {
            throw std::runtime_error(std::format("Expected INFO, got: [{}]", info_line));
        }

        logger.info("NATS-CLIENT: Parsing INFO JSON...");
        process_info(info_line.substr(5));

        // Perform TLS handshake if needed
        co_await socket_->handshake();

        // Send CONNECT message followed by PING (to probe connection)
        const std::string connect_msg = prepare_connect_msg();
        logger.info("NATS-CLIENT: Sending CONNECT...");
        co_await socket_->write(asio::buffer(connect_msg));

        // This ensures the server will respond, completing the handshake
        logger.info("NATS-CLIENT: Sending initial PING...");
        const std::string ping_msg = "PING\r\n";
        co_await socket_->write(asio::buffer(ping_msg));

        // Read server responses until we get PONG (response to our PING)
        // Server may send: +OK, PING (which we must PONG), or our PONG response
        bool handshake_complete = false;
        int max_handshake_messages = 10; // Safety limit
        int message_count = 0;

        while (!handshake_complete && message_count < max_handshake_messages) {
            message_count++;
            auto bytes_read = co_await socket_->read_until(read_buf_, Parser::CRLF);
            logger.info(std::format("NATS-CLIENT: Read {} bytes response, buffer size: {}", bytes_read, read_buf_.size()));

            std::string response_line;
            {
                std::istream is(&read_buf_);
                std::getline(is, response_line);
            }

            if (!response_line.empty() && response_line.back() == '\r') {
                response_line.pop_back();
            }

            logger.info(std::format("NATS-CLIENT: Server response: [{}]", response_line));

            if (response_line.starts_with("PONG")) {
                // This is response to our PING - handshake complete!
                logger.info("NATS-CLIENT: Received PONG - handshake complete");
                handshake_complete = true;
            } else if (response_line.starts_with("PING")) {
                // Server sent PING, we must respond with PONG
                logger.info("NATS-CLIENT: Received PING, sending PONG...");
                const std::string pong_msg = "PONG\r\n";
                co_await socket_->write(asio::buffer(pong_msg));
                // Continue loop to get PONG response to our PING
            } else if (response_line.starts_with("+OK")) {
                logger.info("NATS-CLIENT: Received +OK");
                // Continue - still waiting for PONG to our PING
            } else if (response_line.starts_with("-ERR")) {
                throw std::runtime_error(std::format("Server rejected CONNECT: {}", response_line));
            } else if (response_line.starts_with("INFO")) {
                // Some servers send INFO again, just ignore
                logger.info("NATS-CLIENT: Received additional INFO, ignoring");
            } else {
                logger.info(std::format("NATS-CLIENT: Unexpected response during handshake: {}", response_line));
            }
        }

        if (!handshake_complete) {
            throw std::runtime_error("Handshake did not complete - no PONG received");
        }

        logger.info("NATS-CLIENT: Connection successful.");
        state_.store(State::CONNECTED);

        co_await asio::post(strand_, use_awaitable_exec);
        on_connected(self);

        start_ping_timer(self);

        co_await run_reader_loop(self);
    }

    asio_awaitable run_reader_loop(std::shared_ptr<NatsConnection> self) {
        int message_count = 0;
        while (state_.load() == State::CONNECTED) {
            [[maybe_unused]] auto bytes_read_hdr = co_await socket_->read_until(read_buf_, Parser::CRLF);
            message_count++;
            std::istream is_header(&read_buf_);
            std::string header_line_str;
            std::getline(is_header, header_line_str);
            if (!header_line_str.empty() && header_line_str.back() == '\r') {
                header_line_str.pop_back();
            }

            logger.info(std::format("NATS-CLIENT: Reader loop received (msg #{}): [{}]", message_count, header_line_str));

            auto header = Parser::parse_header_line(header_line_str);

            switch (header.type) {
                case Parser::MsgType::MSG:
                    logger.info("NATS-CLIENT: -> Handling MSG");
                    co_await handle_msg(self, header);
                    break;
                case Parser::MsgType::HMSG:
                    logger.info("NATS-CLIENT: -> Handling HMSG");
                    co_await handle_hmsg(self, header);
                    break;
                case Parser::MsgType::PING:
                    logger.info("NATS-CLIENT: -> Handling PING");
                    co_spawn(ioc_, handle_ping(self), asio::detached);
                    break;
                case Parser::MsgType::PONG:
                    logger.info("NATS-CLIENT: -> Received PONG (ignored)");
                    break;
                case Parser::MsgType::OK:
                    logger.info("NATS-CLIENT: -> Received +OK (ignored)");
                    break;
                case Parser::MsgType::ERR:
                    logger.error(std::format("NATS-CLIENT: Received error: {}", header.error_msg));
                    break;
                default:
                     logger.info(std::format("NATS-CLIENT: Received unknown command: {}", header_line_str));
            }
        }
        logger.info(std::format("NATS-CLIENT: *** READER LOOP EXITED (state: {}) ***", (int)state_.load()));
    }

    // Message Handlers (Coroutines)

    asio_awaitable handle_ping([[maybe_unused]] std::shared_ptr<NatsConnection> self) {
        const std::string pong_msg = "PONG\r\n";
        co_await socket_->write(asio::buffer(pong_msg));
    }

    asio_awaitable handle_msg(std::shared_ptr<NatsConnection> self, Parser::MsgHeader header) {
        std::size_t payload_size = header.total_bytes;
        std::size_t bytes_needed = payload_size + 2; // +2 for \r\n
        std::size_t bytes_already_available = read_buf_.size();
        if (bytes_needed > bytes_already_available) {
            std::size_t bytes_to_read = bytes_needed - bytes_already_available;
            co_await socket_->read_exactly(read_buf_, asio::transfer_exactly(bytes_to_read));
        }

        Buffer packet(payload_size);
        read_buf_.sgetn(reinterpret_cast<char*>(packet.data()), payload_size);
        read_buf_.consume(2); // Consume \r\n

        co_await asio::post(strand_, use_awaitable_exec);
        hmsg_header_map_sv_.clear(); // No headers
        dispatch_message(self, header.sid, header.subject, packet, hmsg_header_map_sv_);
    }

    asio_awaitable handle_hmsg(std::shared_ptr<NatsConnection> self, Parser::MsgHeader header) {
        std::size_t header_size = header.header_bytes;
        std::size_t total_size = header.total_bytes;
        std::size_t payload_size = total_size - header_size;
        std::size_t bytes_needed = total_size + 2; // +2 for \r\n
        std::size_t bytes_already_available = read_buf_.size();
        if (bytes_needed > bytes_already_available) {
            std::size_t bytes_to_read = bytes_needed - bytes_already_available;
            co_await socket_->read_exactly(read_buf_, asio::transfer_exactly(bytes_to_read));
        }
        header_parse_buffer_.resize(header_size);
        read_buf_.sgetn(header_parse_buffer_.data(), header_size);

        logger.info(std::format("NATS-CLIENT: Raw headers ({} bytes): [{}]", header_size, std::string_view(header_parse_buffer_.data(), std::min(header_size, size_t(200)))));

        parse_hmsg_headers(header_parse_buffer_);

        Buffer packet(payload_size);
        read_buf_.sgetn(reinterpret_cast<char*>(packet.data()), payload_size);

        logger.info(std::format("NATS-CLIENT: Payload ({} bytes): [{}]", payload_size, std::string(reinterpret_cast<char*>(packet.data()), std::min(payload_size, size_t(100)))));

        read_buf_.consume(2); // Consume \r\n

        co_await asio::post(strand_, use_awaitable_exec);
        dispatch_message(self, header.sid, header.subject, packet, hmsg_header_map_sv_);
    }

    // Helper Functions

    void on_connected(std::shared_ptr<NatsConnection> self) {
        for (auto& [subject, sub_data] : subscriptions_) {
            if (!sub_data.endpoints.empty()) {
                sub_data.active = false;
                co_spawn(strand_, do_subscribe(self, subject), asio::detached);
            }
        }

        while (!pending_writes_.empty()) {
            auto req = std::move(pending_writes_.front());
            pending_writes_.pop();
            co_spawn(strand_,
                do_publish(self, std::move(req.subject), std::move(req.headers), std::move(req.payload), std::move(req.callback)),
                asio::detached
            );
        }
    }

    void fail_all_pending_writes(std::string_view error) {
        while (!pending_writes_.empty()) {
            auto& req = pending_writes_.front();
            if (req.callback) {
                asio::post(ioc_, [cb = std::move(req.callback), err = std::string(error)] {
                    cb(false, err);
                });
            }
            pending_writes_.pop();
        }
    }

    void start_ping_timer(std::shared_ptr<NatsConnection> self) {
        ping_timer_.expires_after(std::chrono::minutes(1));
        ping_timer_.async_wait([this, self](const asio_system::error_code& ec) {
            if (ec || state_.load() != State::CONNECTED) return;

            const std::string ping_msg = "PING\r\n";
            co_spawn(ioc_,
                socket_->write(asio::buffer(ping_msg)),
                [this, self](std::exception_ptr, std::size_t) { start_ping_timer(self); }
            );
        });
    }

    // Internal Logic

    void process_info(std::string_view info) {
        try {
            simdjson::dom::element doc = json_parser_.parse(info);

            // Correctly check for header support
            bool headers = false;
            auto headers_err = doc["headers"].get_bool().get(headers);
            if (headers_err || !headers) {
                logger.error("NATS-CLIENT: Server does not support headers!");
            }

            // Check for nonce
            std::string_view nonce_sv;
            auto nonce_err = doc["nonce"].get_string().get(nonce_sv);

            if (!nonce_err && !nonce_sv.empty()) {
                server_nonce_ = std::string(nonce_sv);
                logger.info("NATS-CLIENT: Received nonce for challenge-response auth.");
            } else {
                server_nonce_.clear();
            }
        } catch (const std::exception& e) {
            logger.error(std::format("NATS-CLIENT: Failed to parse server INFO: {}", e.what()));
            server_nonce_.clear(); // Ensure nonce is clear on parse error
        }
    }

    std::string prepare_connect_msg() {
        std::stringstream ss;
        ss << R"({)";
        ss << R"("verbose":false,"pedantic":false)";
        ss << R"(,"headers":true)";
        ss << R"(,"lang":"cpp","version":"alenats-0.9")";

        if (auth_.has_value()) {
            const auto& auth = auth_.value();
            if (!auth.token.empty() && !auth.key.empty() && !server_nonce_.empty()) {
                logger.info("NATS-CLIENT: Attempting NKEY+JWT challenge-response authentication.");
                try {
                    // Add the User JWT
                    ss << R"(,"jwt":")" << auth.token << R"(")";

                    // Sign the nonce with the NKEY seed
                    std::string signature = Nats::Crypto::SignWithNKey(auth.key, server_nonce_);

                    // Add the Base64-URL-encoded signature
                    ss << R"(,"sig":")" << signature << R"(")";
                } catch (const std::exception& e) {
                    logger.error(std::format("NATS-CLIENT: NKEY signing failed: {}", e.what()));
                }
            }
            else if (!auth.token.empty()) {
                logger.info("NATS-CLIENT: Using simple token authentication.");
                ss << R"(,"auth_token":")" << auth.token << R"(")";
            }
            // Username / Password Authentication
            else if (!auth.username.empty()) {
                logger.info("NATS-CLIENT: Using username/password authentication.");
                ss << R"(,"user":")" << auth.username << R"(")";
                if (!auth.password.empty()) {
                    ss << R"(,"pass":")" << auth.password << R"(")";
                }
            }
        }

        ss << R"(})";

        return std::format("CONNECT {}\r\n", ss.str());
    }

    void parse_hmsg_headers(std::string_view header_data) {
        hmsg_header_map_sv_.clear();
        hmsg_header_map_str_.clear();

        std::stringstream ss{std::string(header_data)};
        std::string header_line;
        std::getline(ss, header_line); // Skip NATS/1.0

        while(std::getline(ss, header_line) && header_line.length() > 1) {
            header_line.pop_back(); // remove \r
            if(auto pos = header_line.find(':'); pos != std::string_view::npos) {
                std::string key = std::string(std::string_view(header_line).substr(0, pos));
                std::string_view val_sv = std::string_view(header_line).substr(pos + 1);
                val_sv.remove_prefix(std::min(val_sv.find_first_not_of(" \t"), val_sv.length()));

                auto [it, inserted] = hmsg_header_map_str_.try_emplace(std::move(key), std::string(val_sv));
                hmsg_header_map_sv_[it->first] = it->second;
            }
        }
    }

    void dispatch_message(
        [[maybe_unused]] std::shared_ptr<NatsConnection> self,
        std::string_view sid_sv,
        std::string_view subject_sv,
        const Buffer& packet,
        const std::map<std::string_view, std::string_view>& headers
    ) {
        std::string sid_str(sid_sv);
        auto it = subscriptions_.find(sid_str);

        if (it == subscriptions_.end()) {
            logger.error(std::format("NATS-CLIENT: No subscription found for SID: [{}]", sid_str));
            logger.error("NATS-CLIENT: Available subscriptions:");
            for (const auto& [sub_key, sub_data] : subscriptions_) {
                logger.error(std::format("  - [{}] (active: {}, endpoints: {})",
                    sub_key, sub_data.active, sub_data.endpoints.size()));
            }
            return;
        }

        std::map<std::string, std::string> header_map_owned;
        for (auto const& [key, val] : headers) {
            header_map_owned.emplace(std::string(key), std::string(val));
        }

        auto endpoints_copy = it->second.endpoints;
        for (auto& weak_ep : endpoints_copy) {
            if (auto ep = weak_ep.lock()) {
                ep->dispatch_packet(packet, subject_sv, header_map_owned);
            }
        }
    }

    // NatsConnection Implementation

    void stop() {
        if (state_.exchange(State::STOPPED) == State::STOPPED) {
            return;
        }

        asio::post(strand_, [this, self = shared_from_this()] {
            ping_timer_.cancel();
            connect_timer_.cancel();
            if (socket_) socket_->close();
            subscriptions_.clear();
            fail_all_pending_writes("Connection stopped");
        });
    }

    void subscribe(
        std::string subject,
        std::weak_ptr<Subscription> endpoint
    ) override {
        logger.info(std::format("NATS-CLIENT: subscribe() called for subject: [{}]", subject));
        asio::post(strand_, [this, self = shared_from_this(), sub = std::move(subject), ep = std::move(endpoint)]() {
            if (state_.load() == State::STOPPED) {
                logger.info("NATS-CLIENT: subscribe aborted - connection stopped");
                return;
            }

            auto& sub_data = subscriptions_[sub];
            bool first_subscriber = sub_data.endpoints.empty();
            sub_data.endpoints.insert(std::move(ep));

            logger.info(std::format("NATS-CLIENT: Added endpoint to subscription [{}], first_subscriber: {}, state: {}, active: {}",
                sub, first_subscriber, (int)state_.load(), sub_data.active));

            if (first_subscriber && state_.load() == State::CONNECTED && !sub_data.active) {
                logger.info(std::format("NATS-CLIENT: Spawning do_subscribe for [{}]", sub));
                co_spawn(strand_, do_subscribe(self, sub), asio::detached);
            } else {
                logger.info(std::format("NATS-CLIENT: NOT spawning do_subscribe (first:{}, connected:{}, active:{})",
                    first_subscriber, state_.load() == State::CONNECTED, sub_data.active));
            }
        });
    }

    void unsubscribe(std::weak_ptr<Subscription> endpoint) override {
        asio::post(strand_, [this, self = shared_from_this(), ep = std::move(endpoint)]() {
            if (state_.load() == State::STOPPED) return;

            for (auto it = subscriptions_.begin(); it != subscriptions_.end(); ) {
                it->second.endpoints.erase(ep);

                if (it->second.endpoints.empty()) {
                    const bool was_active = it->second.active;
                    it->second.active = false;

                    if (was_active && state_.load() == State::CONNECTED) {
                        co_spawn(strand_, do_unsubscribe(self, it->first), asio::detached);
                    }

                    it = subscriptions_.erase(it);
                } else {
                    ++it;
                }
            }
        });
    }

    void async_publish(
        std::string subject,
        Buffer payload,
        PublishCallback handler
    ) override {
        async_publish(std::move(subject), {}, std::move(payload), std::move(handler));
    }

    void async_publish(
        std::string subject,
        std::map<std::string, std::string> headers,
        Buffer payload,
        PublishCallback handler
    ) override {
        asio::post(strand_, [
            this, self = shared_from_this(),
            sub = std::move(subject),
            hdrs = std::move(headers),
            pay = std::move(payload),
            cb = std::move(handler)
        ]() mutable {
            if (state_.load() == State::STOPPED) {
                if(cb) asio::post(ioc_, [cb = std::move(cb)] { cb(false, "Connection stopped"); });
                return;
            }

            if (state_.load() != State::CONNECTED) {
                logger.info("NATS-CLIENT: [Adapter] Queuing publish, not connected yet.");
                pending_writes_.push({std::move(sub), std::move(hdrs), std::move(pay), std::move(cb)});
                return;
            }

            co_spawn(strand_,
                do_publish(self, std::move(sub), std::move(hdrs), std::move(pay), std::move(cb)),
                asio::detached
            );
        });
    }

    // Internal Publish/Subscribe Coroutines

    asio_awaitable do_publish(
        [[maybe_unused]] std::shared_ptr<NatsConnection> self,
        std::string subject,
        std::map<std::string, std::string> headers,
        Buffer payload,
        PublishCallback handler
    ) {
        std::string header_line;
        std::string header_blob;
        std::vector<asio::const_buffer> buffers;

        try {
            if (headers.empty()) {
                header_line = std::format("PUB {} {}\r\n", subject, payload.size());
                buffers.emplace_back(asio::buffer(header_line));
                buffers.emplace_back(asio::buffer(payload));
            } else {
                std::stringstream ss;
                ss << "NATS/1.0\r\n";
                for (const auto& [key, value] : headers) {
                    ss << key << ":" << value << "\r\n";
                }
                ss << "\r\n";
                header_blob = ss.str();

                size_t total_payload_size = header_blob.length() + payload.size();
                header_line = std::format("HPUB {} {} {}\r\n", subject, header_blob.length(), total_payload_size);

                buffers.emplace_back(asio::buffer(header_line));
                buffers.emplace_back(asio::buffer(header_blob));
                buffers.emplace_back(asio::buffer(payload));
            }

            // Add final CRLF
            static const std::string final_crlf = "\r\n";
            buffers.emplace_back(asio::buffer(final_crlf));

            co_await socket_->write(buffers);
            if(handler) asio::post(ioc_, [cb = std::move(handler)]{ cb(true, ""); });

        } catch (const std::exception& e) {
            logger.error(std::format("NATS-CLIENT: Publish error: {}", e.what()));
            if(handler) asio::post(ioc_, [cb = std::move(handler), err = std::string(e.what())]{ cb(false, err); });
            if (socket_) socket_->close();
        }
    }

    asio_awaitable do_subscribe([[maybe_unused]] std::shared_ptr<NatsConnection> self, const std::string& subject) {
        try {
            auto& sub_data = subscriptions_.at(subject);
            std::string sub_msg = std::format("SUB {} {}\r\n", subject, subject); // Using subject as SID

            logger.info(std::format("NATS-CLIENT: Sending SUB command: [{}]", sub_msg.substr(0, sub_msg.length()-2)));

            co_await socket_->write(asio::buffer(sub_msg));
            sub_data.active = true;
            logger.info(std::format("NATS-CLIENT: [Adapter] Subscribed to {}", subject));
            logger.info(std::format("NATS-CLIENT: subscriptions_ now contains {} entries", subscriptions_.size()));

            for (const auto& [key, data] : subscriptions_) {
                logger.info(std::format("NATS-CLIENT:   - [{}] active:{}, endpoints:{}",
                    key, data.active, data.endpoints.size()));
            }
        } catch (const std::exception& e) {
            logger.error(std::format("NATS-CLIENT: Subscribe error: {}", e.what()));
            if (socket_) socket_->close();
        }
    }

    asio_awaitable do_unsubscribe([[maybe_unused]] std::shared_ptr<NatsConnection> self, const std::string& subject) {
        try {
            std::string unsub_msg = std::format("UNSUB {}\r\n", subject); // Using subject as SID
            co_await socket_->write(asio::buffer(unsub_msg));
            logger.info(std::format("NATS-CLIENT: [Adapter] Unsubscribed from {}", subject));
        } catch (const std::exception& e) {
            logger.error(std::format("NATS-CLIENT: Unsubscribe error: {}", e.what()));
            if (socket_) socket_->close();
        }
    }

    asio::any_io_executor get_executor() const override { return strand_; }
    Nats::ClientState get_state() const override { return state_.load(); }
};

ConnectionManager::ConnectionManager(asio::io_context& ioc)
    : pimpl_(std::make_unique<Impl>(ioc))
{
}

ConnectionManager::~ConnectionManager() = default;

void ConnectionManager::async_get_connection(
    const std::string& host,
    const std::string& port,
    const std::optional<Nats::Credentials>& auth,
    bool use_ssl,
    std::function<void(std::shared_ptr<Nats::Connection>)> handler
) {
    std::string key = host + ":" + port;
    if (auth) {
        key += ":" + auth->username;
    }
    key += (use_ssl ? ":ssl" : ":tcp");

    auto factory = [this, host, port, auth, use_ssl]() -> std::shared_ptr<Nats::Connection> {
        auto conn = std::make_shared<Nats::NatsConnection>(pimpl_->ioc_);
        conn->start_client(conn, host, port, auth, use_ssl);
        return conn;
    };

    pimpl_->pool_.async_get_or_create(
        std::move(key),
        std::move(factory),
        std::move(handler),
        shared_from_this()
    );
}

} // namespace Nats
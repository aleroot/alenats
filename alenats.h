/*
 * alenats.h - A simple C++23 Asio NATS Client
 *
 * Header file for the alenats library.
 *
 * Dependencies:
 * - Asio
 * - OpenSSL
 * - simdjson
 * 
 * License: Boost Software License v1
 * 
 * @author Alessio Pollero
 */

#pragma once

#ifdef ASIO_STANDALONE
#include <asio/io_context.hpp>
#include <asio/strand.hpp>
#include <asio/post.hpp>
#include <asio/bind_executor.hpp>
#include <asio/ssl.hpp>
#include <asio/steady_timer.hpp>
#else
#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#endif

#include <memory>
#include <string>
#include <map>
#include <set>
#include <atomic>
#include <functional>
#include <optional>
#include <string_view>
#include <vector>
#include <cstddef>
#include <span>
#include <iostream>

namespace simdjson { namespace dom { class parser; class element; } }

namespace Nats {
    #ifndef ASIO_STANDALONE 
    namespace asio = boost::asio;
    #endif
    using Buffer = std::vector<std::byte>;

    /**
     * @brief Authentication details for the NATS connection.
     */
    struct Credentials {
        std::string username;
        std::string password;
        std::string token;
        std::string key; // NKEY Seed
    };

    /**
     * @brief Connection state enum.
     */
    enum class ClientState {
        DISCONNECTED,
        CONNECTING,
        CONNECTED,
        STOPPED
    };

    /**
     * @struct Logger
     * @brief Injectable logging interface for the Nats namespace.
     */
    struct Logger {
        using LogFunc = std::function<void(std::string_view)>;
        
        LogFunc info = [](std::string_view) { /* no-op */ };
        LogFunc error = [](std::string_view) { /* no-op */ };
    };

    /**
     * @brief Global logger instance for the Nats namespace.
     */
    inline Logger logger;

    /**
     * @brief Utility function for debug logging using std::print.
     */
    inline void PRINT_LOG(std::string_view msg) {
       std::println(std::cerr, "{}", msg);
    }

    /**
     * @brief Helper to convert string to Nats::Buffer (std::vector<std::byte>)
     */
    inline Buffer to_buffer(std::string_view s) {
        const auto bytes = std::as_bytes(std::span{s});
        return Nats::Buffer(bytes.begin(), bytes.end());
    }
    
    /**
     * @class Subscription
     * @brief A functional interface for message handling.
     *
     * Any class wishing to receive messages must implement this interface
     * and pass a std::weak_ptr of itself to Nats::Connection::subscribe.
     */
    class Subscription {
    public:
        virtual ~Subscription() = default;

        /**
         * @brief Called by the NatsConnection when a message arrives.
         * @param packet The message payload.
         * @param subject The full NATS subject the message arrived on.
         * @param headers The map of headers (owned strings).
         */
        virtual void dispatch_packet(
            const Buffer& packet, 
            std::string_view subject,
            const std::map<std::string, std::string>& headers
        ) = 0;
    };

    /**
     * @interface Connection
     * @brief The public interface for a shared NATS connection.
     */
    class Connection {
    public:
        virtual ~Connection() = default;

        /**
         * @brief Subscribes to a NATS subject.
         * @param subject The NATS subject (e.g., "foo.bar" or "foo.*").
         * @param endpoint A weak_ptr to an object implementing Subscription.
         * The connection holds this weak_ptr and will
         * automatically handle the endpoint's destruction.
         */
        virtual void subscribe(
            std::string subject,
            std::weak_ptr<Subscription> endpoint
        ) = 0;

        /**
         * @brief Unsubscribes an endpoint from all subjects it was listening to.
         */
        virtual void unsubscribe(
            std::weak_ptr<Subscription> endpoint
        ) = 0;

        /**
         * @brief Asynchronously publishes a message with headers to a NATS subject.
         */
        virtual void async_publish(
            std::string subject,
            std::map<std::string, std::string> headers,
            Buffer payload,
            std::function<void(bool success, std::string_view error)> handler
        ) = 0;

        /**
         * @brief Asynchronously publishes a message (no headers) to a NATS subject.
         */
        virtual void async_publish(
            std::string subject,
            Buffer payload,
            std::function<void(bool success, std::string_view error)> handler
        ) = 0;


        /**
         * @brief Gets the executor (strand) for this connection.
         */
        virtual asio::any_io_executor get_executor() const = 0;

        /**
         * @brief Gets the current atomic state of the connection.
         */
        virtual Nats::ClientState get_state() const = 0;
    };

    /**
     * @brief A generic, thread-safe connection pool/manager.
     *
     * This template class manages a pool of shared connections
     * identified by a string key. It handles the "get or create" logic in a 
     * thread-safe manner using a strand.
     *
     * @tparam T The interface type of the connection (e.g., NatsConnection).
     */
    template <typename T>
    class ConnectionPool {
    public:
        /**
         * @brief A synchronous factory function that creates and *starts* a new connection.
         * @return A shared_ptr to the newly created and started connection.
         */
        using FactoryFunc = std::function<std::shared_ptr<T>()>;

        /**
         * @brief The callback invoked with the connection (or nullptr on failure).
         */
        using HandlerFunc = std::function<void(std::shared_ptr<T>)>;

        /**
         * @param ioc The io_context to use for posting handlers and for the strand.
         */
        explicit ConnectionPool(asio::io_context& ioc) 
            : ioc_(ioc), strand_(ioc.get_executor()) {}

        /**
         * @brief Gets the executor (strand) for this pool.
         */
        asio::any_io_executor get_executor() const {
            return strand_;
        }

        /**
         * @brief Asynchronously gets an existing connection or creates a new one.
         * * @param key The unique key for this connection (e.g., "user@host:port:ssl").
         * @param factory The factory function to run if a new connection is needed.
         * @param handler The callback to be invoked with the resulting connection.
         */
        void async_get_or_create(
            std::string key, 
            FactoryFunc factory, 
            HandlerFunc handler,
            std::shared_ptr<void> anchor = nullptr
        ) {
            // Post the entire logic to the strand to ensure map access is thread-safe
            asio::post(strand_, [
                this, 
                key = std::move(key), 
                factory = std::move(factory), 
                handler = std::move(handler),
                anchor
            ]() mutable {
                
                // Check if a valid connection already exists in the pool
                if (auto it = pool_.find(key); it != pool_.end()) {
                    if (auto conn = it->second.lock()) {
                        asio::post(ioc_, [h = std::move(handler), c = std::move(conn)]() {
                            h(c);
                        });
                        return;
                    } else {
                        pool_.erase(it);
                    }
                }

                // No valid connection. We must create a new one.
                std::shared_ptr<T> new_conn;
                try {
                    new_conn = factory(); 
                } catch (const std::exception& e) {
                    asio::post(ioc_, [h = std::move(handler)]() { h(nullptr); });
                    return;
                }

                if (!new_conn) {
                    asio::post(ioc_, [h = std::move(handler)]() { h(nullptr); });
                    return;
                }
                pool_[key] = new_conn;

                // Post the successful handler back to the main context.
                asio::post(ioc_, [h = std::move(handler), c = std::move(new_conn)]() {
                    h(c);
                });
            });
        }

    private:
        asio::io_context& ioc_;
        asio::strand<asio::io_context::executor_type> strand_;
        std::map<std::string, std::weak_ptr<T>> pool_;
    };

    /**
     * @class ConnectionManager
     * @brief Manages shared Nats::Connection instances.
     *
     * This class ensures that only one connection is created per
     * unique destination (host, port, auth, ssl).
     */
    class ConnectionManager : public std::enable_shared_from_this<ConnectionManager> {
    public:
        explicit ConnectionManager(asio::io_context& ioc);
        ~ConnectionManager();
        
        ConnectionManager(const ConnectionManager&) = delete;
        ConnectionManager& operator=(const ConnectionManager&) = delete;

        /**
         * @brief Gets or creates a shared connection for a given destination.
         * @param handler A callback that will be invoked with the shared connection.
         */
        void async_get_connection(
            const std::string& host,
            const std::string& port,
            const std::optional<Nats::Credentials>& auth,
            bool use_ssl,
            std::function<void(std::shared_ptr<Nats::Connection>)> handler
        );

    private:
        struct Impl;
        std::unique_ptr<Impl> pimpl_;
    };

}

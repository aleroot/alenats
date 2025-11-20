//
#include "alenats.h"

#ifdef ASIO_STANDALONE
#include <asio/io_context.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/signal_set.hpp>
#else
#include <boost/asio/io_context.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/signal_set.hpp>
#endif

#include <print>
#include <chrono>
#include <string_view>

using namespace std::chrono_literals;

#ifndef ASIO_STANDALONE 
namespace asio = boost::asio;
#endif

/**
 * @brief A simple Service that listens for requests and sends a reply.
 */
class TimeService : public Nats::Subscription, 
                    public std::enable_shared_from_this<TimeService> {
    std::shared_ptr<Nats::Connection> conn_;

public:
    TimeService(std::shared_ptr<Nats::Connection> conn) : conn_(conn) {}

    void dispatch_packet(
        const Nats::Buffer& payload, 
        std::string_view subject,
        std::string_view reply_to,
        const std::map<std::string, std::string>& headers
    ) override {
        if (!reply_to.empty()) {
            std::string inbox(reply_to);
            std::string response = "The time is now!";
            conn_->async_publish(inbox, Nats::to_buffer(response), nullptr);
        }
    }

    void start() {
        conn_->subscribe("service.time", weak_from_this());
        std::println("   [Service] Listening on 'service.time'...");
    }
};

/**
 * Performs a request to the service we created above.
 */
asio::awaitable<void> run_request_test(std::shared_ptr<Nats::Connection> conn) {    
    try {
        // Send a request and await the reply
        auto reply = co_await conn->request(
            "service.time",                  // Subject
            Nats::to_buffer("What time?"),   // Payload
            2s                               // Timeout
        );
        
        std::println("-> ✓ Received reply: '{}'", Nats::view_string(reply.payload));
        
    } catch (const std::exception& e) {
        std::println(stderr, "-> ✗ Request failed: {}", e.what());
    }
}

/**
 * Main coroutine logic
 */
asio::awaitable<void> run_examples(asio::io_context& ioc) {
    try {
        const std::vector<Nats::ServerAddress> cluster = { {"demo.nats.io", "4222"}};
        auto mgr = std::make_shared<Nats::ConnectionManager>(ioc);
        auto conn = co_await mgr->connect(cluster);
        
        if (!conn) {
            std::println(stderr, "✗ Failed to connect to NATS server");
            co_return;
        }

        auto service = std::make_shared<TimeService>(conn);
        service->start();

        
        // Send Request
        co_await run_request_test(conn);
        
    } catch (const std::exception& e) {
        std::println(stderr, "✗ Fatal error: {}", e.what());
    }
}

int main() {
    // Enable internal logging from the NATS client
    Nats::logger.info = Nats::PRINT_LOG;
    Nats::logger.error = Nats::PRINT_LOG;
    try {
        asio::io_context ioc;
        asio::signal_set signals(ioc, SIGINT, SIGTERM);
        signals.async_wait([&](auto, auto) {
            std::println("\nShutting down...");
            ioc.stop();
        });
        
        asio::co_spawn(ioc, run_examples(ioc), [&ioc](std::exception_ptr e) {
            if (e) {
                try { std::rethrow_exception(e); } 
                catch (const std::exception& ex) {
                    std::println(stderr, "Coroutine exception: {}", ex.what());
                }
            }
            ioc.stop();
        });
        
        ioc.run();
        
    } catch (const std::exception& e) {
        std::println(stderr, "Exception: {}", e.what());
        return 1;
    }
    
    return 0;
}
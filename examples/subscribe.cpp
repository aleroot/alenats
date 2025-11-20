#include "alenats.h"

#ifdef ASIO_STANDALONE
#include <asio/io_context.hpp>
#include <asio/signal_set.hpp>
#else
#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>
#endif

#include <memory>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <print>

// Your class must implement Nats::Subscription to receive messages.
// It must also use enable_shared_from_this to provide a weak_ptr.
class MySubscriber : public Nats::Subscription,
                     public std::enable_shared_from_this<MySubscriber> 
{
    std::shared_ptr<Nats::Connection> conn_;

public:
    MySubscriber(std::shared_ptr<Nats::Connection> conn) : conn_(conn) {}

    // This is the message handler implementation
    void dispatch_packet(
        const Nats::Buffer& packet, 
        std::string_view subject,
        std::string_view reply_to,
        const std::map<std::string, std::string>& headers
    ) override {
        std::string payload(
            reinterpret_cast<const char*>(packet.data()), packet.size()
        );
        
        std::println(
            "==> Received message on subject [{}]:",
            subject
        );

        if (!reply_to.empty()) {
            std::println("  Reply-To: {}", reply_to);
        }
        
        if (!headers.empty()) {
            std::println("  Headers:");
            for(const auto& [key, val] : headers) {
                std::println("    {}: {}", key, val);
            }
        }
        std::println("  Payload: {}", payload);
    }
    
    void start() {
        conn_->subscribe("foo.bar", weak_from_this());
        conn_->subscribe("another.subject", weak_from_this());
        conn_->subscribe("with.headers", weak_from_this());
        
        std::println("Subscribed to 'foo.bar', 'another.subject', and 'with.headers'");
        std::println("Waiting for messages... Press Ctrl+C to exit.");
    }
    
    void stop() {
        // This will unsubscribe this instance from all subjects
        conn_->unsubscribe(weak_from_this());
        std::println("Unsubscribed from all subjects.");
    }
};

#ifndef ASIO_STANDALONE 
namespace asio = boost::asio;
#endif

int main() {
    try {
        asio::io_context ioc;

        // Enable internal logging from the NATS client
        Nats::logger.info = Nats::PRINT_LOG;
        Nats::logger.error = Nats::PRINT_LOG;

        auto conn_mgr = std::make_shared<Nats::ConnectionManager>(ioc);
        std::shared_ptr<MySubscriber> subscriber;
        
        conn_mgr->async_get_connection(
            "demo.nats.io", // NATS demo server
            "4222",
            std::nullopt, // No auth
            false,        // No SSL
            [&](std::shared_ptr<Nats::Connection> conn) {
                
                if (!conn) {
                    std::println(std::cerr, "Failed to get connection");
                    return;
                }
                
                // Create and start the subscriber
                subscriber = std::make_shared<MySubscriber>(conn);
                subscriber->start();
            }
        );

        asio::signal_set signals(ioc, SIGINT, SIGTERM);
        signals.async_wait([&](auto, auto) {
            std::println("\nShutting down...");
            if (subscriber) {
                subscriber->stop();
            }
            ioc.stop();
        });
        
        ioc.run();
    } catch (const std::exception& e) {
        std::println(std::cerr, "Exception: {}", e.what());
        return 1;
    }
    return 0;
}
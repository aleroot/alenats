#include "alenats.h"

#ifdef ASIO_STANDALONE
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#else
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#endif

#include <memory>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <print>

#ifndef ASIO_STANDALONE 
namespace asio = boost::asio;
#endif

int main() {
    try {
        asio::io_context ioc;
        
        // Optional: Enable logging
        // Nats::logger.info = Nats::PRINT_LOG;
        // Nats::logger.error = Nats::PRINT_LOG;
        
        auto conn_mgr = std::make_shared<Nats::ConnectionManager>(ioc);
        
        conn_mgr->async_get_connection(
            "demo.nats.io", // NATS demo server
            "4222",
            std::nullopt, // No auth
            false,        // No SSL
            [&ioc](std::shared_ptr<Nats::Connection> conn) {
                
                if (!conn) {
                    std::println(std::cerr, "Failed to get connection");
                    ioc.stop();
                    return;
                }
                
                std::println("Got connection, publishing messages...");

                // 1. Publish a simple message
                conn->async_publish(
                    "foo.bar",
                    Nats::to_buffer("Hello from alenats!"),
                    [](bool success, std::string_view error) {
                        if (success) {
                            std::println("Publish to 'foo.bar' successful!");
                        } else {
                            std::println(std::cerr, "Publish failed: {}", error);
                        }
                    }
                );

                // 2. Publish a message with headers
                std::map<std::string, std::string> headers;
                headers["X-My-Header"] = "alenats-is-cool";
                headers["Content-Type"] = "text/plain";
                
                conn->async_publish(
                    "with.headers",
                    std::move(headers),
                    Nats::to_buffer("This message has headers!"),
                    [](bool success, std::string_view error) {
                        if (success) {
                            std::println("Publish to 'with.headers' successful!");
                        } else {
                            std::println(std::cerr, "Publish failed: {}", error);
                        }
                    }
                );
                
                // 3. Publish and then stop the context
                conn->async_publish(
                    "another.subject",
                    Nats::to_buffer("Last message"),
                    [&ioc](bool success, std::string_view error) {
                        std::println("Final publish complete. Stopping context.");
                        // Stop the io_context after a short delay
                        // to ensure messages are sent.
                        auto timer = std::make_shared<asio::steady_timer>(ioc);
                        timer->expires_after(std::chrono::seconds(1));
                        timer->async_wait([&ioc, timer](auto...){
                            ioc.stop();
                        });
                    }
                );
            }
        );
        
        ioc.run();
    } catch (const std::exception& e) {
        std::println(std::cerr, "Exception: {}", e.what());
        return 1;
    }
    return 0;
}

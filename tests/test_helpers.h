#pragma once

#include "../alenats.h"
#include <catch2/catch_all.hpp>

#ifdef ASIO_STANDALONE
    #include <asio/io_context.hpp>
#else
    #include <boost/asio/io_context.hpp>
    namespace asio = boost::asio;
#endif

#include <chrono>
#include <memory>
#include <thread>

namespace TestHelpers {

/**
 * Run io_context for a limited time or until work completes
 */
inline void run_io_context_for(asio::io_context& ioc, std::chrono::milliseconds timeout) {
    auto work_guard = asio::make_work_guard(ioc);

    std::thread runner([&ioc] {
        ioc.run();
    });

    std::this_thread::sleep_for(timeout);
    work_guard.reset();
    ioc.stop();

    if (runner.joinable()) {
        runner.join();
    }

    ioc.restart();
}

/**
 * Create a mock subscriber for testing
 */
class MockSubscriber : public Nats::Subscription {
public:
    void dispatch_packet(
        const Nats::Buffer& payload,
        std::string_view subject,
        std::string_view reply_to, 
        const std::map<std::string, std::string>& headers) override {
        message_count++;
        last_subject = subject;
        last_reply_to = reply_to;
        last_payload = payload;
        last_headers = headers;
    }

    int message_count = 0;
    std::string last_subject;
    std::string last_reply_to;
    Nats::Buffer last_payload;
    std::map<std::string, std::string> last_headers;
};

using Nats::to_buffer;

/**
 * Convert buffer to string (for test assertions)
 */
inline std::string to_string(const Nats::Buffer& buffer) {
    return std::string(Nats::view_string(buffer));
}
} // namespace TestHelpers
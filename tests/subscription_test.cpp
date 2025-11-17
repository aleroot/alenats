#include "test_helpers.h"

using namespace TestHelpers;

// ============================================================================
// HAPPY PATH TESTS
// ============================================================================

TEST_CASE("Subscription: MockSubscriber receives message -> dispatch_packet called") {
    auto subscriber = std::make_shared<MockSubscriber>();

    std::string subject = "test.subject";
    std::string payload = "Hello, NATS!";
    std::map<std::string, std::string> headers{{"key1", "value1"}};

    auto buffer = to_buffer(payload);

    subscriber->dispatch_packet(buffer, subject, headers);

    REQUIRE(subscriber->message_count == 1);
    REQUIRE(subscriber->last_subject == subject);
    REQUIRE(to_string(subscriber->last_payload) == payload);
    REQUIRE(subscriber->last_headers.at("key1") == "value1");
}

TEST_CASE("Subscription: Multiple messages -> Counts correctly") {
    auto subscriber = std::make_shared<MockSubscriber>();

    for (int i = 0; i < 10; ++i) {
        subscriber->dispatch_packet(to_buffer("message"), "subject", {});
    }

    REQUIRE(subscriber->message_count == 10);
}

TEST_CASE("Subscription: Message with empty payload -> Handled correctly") {
    auto subscriber = std::make_shared<MockSubscriber>();

    Nats::Buffer empty_buffer;
    subscriber->dispatch_packet(empty_buffer, "test.subject", {});

    REQUIRE(subscriber->message_count == 1);
    REQUIRE(subscriber->last_payload.empty());
}

TEST_CASE("Subscription: Message with headers -> Headers preserved") {
    auto subscriber = std::make_shared<MockSubscriber>();

    std::map<std::string, std::string> headers{
        {"Content-Type", "application/json"},
        {"X-Custom-Header", "custom-value"}
    };

    subscriber->dispatch_packet(to_buffer("data"), "test.subject", headers);

    REQUIRE(subscriber->message_count == 1);
    REQUIRE(subscriber->last_headers.size() == 2);
    REQUIRE(subscriber->last_headers.at("Content-Type") == "application/json");
    REQUIRE(subscriber->last_headers.at("X-Custom-Header") == "custom-value");
}

// ============================================================================
// UNHAPPY PATH TESTS
// ============================================================================

TEST_CASE("Subscription: Empty subject -> Still processed") {
    auto subscriber = std::make_shared<MockSubscriber>();

    subscriber->dispatch_packet(to_buffer("data"), "", {});

    REQUIRE(subscriber->message_count == 1);
    REQUIRE(subscriber->last_subject.empty());
}

TEST_CASE("Subscription: Subject with special characters -> Preserved correctly") {
    auto subscriber = std::make_shared<MockSubscriber>();

    std::string special_subject = "test.*.wildcard.>";
    subscriber->dispatch_packet(to_buffer("data"), special_subject, {});

    REQUIRE(subscriber->message_count == 1);
    REQUIRE(subscriber->last_subject == special_subject);
}

TEST_CASE("Subscription: Empty headers map -> No crash") {
    auto subscriber = std::make_shared<MockSubscriber>();

    std::map<std::string, std::string> empty_headers;
    subscriber->dispatch_packet(to_buffer("data"), "test.subject", empty_headers);

    REQUIRE(subscriber->message_count == 1);
    REQUIRE(subscriber->last_headers.empty());
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

TEST_CASE("Subscription: Large payload -> Handled correctly") {
    auto subscriber = std::make_shared<MockSubscriber>();

    // Create 1MB payload
    std::string large_payload(1024 * 1024, 'A');
    auto buffer = to_buffer(large_payload);

    subscriber->dispatch_packet(buffer, "test.subject", {});

    REQUIRE(subscriber->message_count == 1);
    REQUIRE(subscriber->last_payload.size() == large_payload.size());
}

TEST_CASE("Subscription: Binary payload (non-UTF8) -> Preserved correctly") {
    auto subscriber = std::make_shared<MockSubscriber>();

    // Create binary payload with non-UTF8 bytes
    Nats::Buffer binary_payload{
        std::byte{0xFF}, std::byte{0xFE}, std::byte{0xFD},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x02}
    };

    subscriber->dispatch_packet(binary_payload, "binary.subject", {});

    REQUIRE(subscriber->message_count == 1);
    REQUIRE(subscriber->last_payload == binary_payload);
}

TEST_CASE("Subscription: Subject with maximum length -> Handled correctly") {
    auto subscriber = std::make_shared<MockSubscriber>();

    // NATS subjects can be very long (limited by protocol, typically around 32KB)
    std::string long_subject(1000, 'a');
    for (int i = 0; i < 10; ++i) {
        long_subject += ".segment" + std::to_string(i);
    }

    subscriber->dispatch_packet(to_buffer("data"), long_subject, {});

    REQUIRE(subscriber->message_count == 1);
    REQUIRE(subscriber->last_subject == long_subject);
}

TEST_CASE("Subscription: Headers with empty values -> Preserved") {
    auto subscriber = std::make_shared<MockSubscriber>();

    std::map<std::string, std::string> headers{
        {"EmptyValue", ""},
        {"NormalKey", "value"}
    };

    subscriber->dispatch_packet(to_buffer("data"), "test.subject", headers);

    REQUIRE(subscriber->message_count == 1);
    REQUIRE(subscriber->last_headers.at("EmptyValue") == "");
    REQUIRE(subscriber->last_headers.at("NormalKey") == "value");
}

// ============================================================================
// NEGATIVE TESTS (Stress, Concurrency)
// ============================================================================

TEST_CASE("Subscription: Rapid sequential messages -> All processed correctly") {
    auto subscriber = std::make_shared<MockSubscriber>();

    constexpr int num_messages = 1000;

    for (int i = 0; i < num_messages; ++i) {
        std::string payload = "Message " + std::to_string(i);
        subscriber->dispatch_packet(to_buffer(payload), "test.subject", {});
    }

    REQUIRE(subscriber->message_count == num_messages);
}

TEST_CASE("Subscription: Multiple subscribers -> Independent state") {
    auto sub1 = std::make_shared<MockSubscriber>();
    auto sub2 = std::make_shared<MockSubscriber>();

    sub1->dispatch_packet(to_buffer("msg1"), "subject1", {});
    sub2->dispatch_packet(to_buffer("msg2"), "subject2", {});
    sub1->dispatch_packet(to_buffer("msg3"), "subject1", {});

    REQUIRE(sub1->message_count == 2);
    REQUIRE(sub2->message_count == 1);
    REQUIRE(sub1->last_subject == "subject1");
    REQUIRE(sub2->last_subject == "subject2");
}

TEST_CASE("Subscription: Subscriber destroyed mid-operation -> Safe with weak_ptr pattern") {
    // This test validates the weak_ptr pattern used by Connection
    std::weak_ptr<MockSubscriber> weak_sub;

    {
        auto subscriber = std::make_shared<MockSubscriber>();
        weak_sub = subscriber;

        REQUIRE(!weak_sub.expired());

        subscriber->dispatch_packet(to_buffer("data"), "test.subject", {});
        REQUIRE(subscriber->message_count == 1);

        // Subscriber destroyed here
    }

    // Weak pointer should now be expired
    REQUIRE(weak_sub.expired());

    // Attempting to lock should return nullptr
    auto locked = weak_sub.lock();
    REQUIRE(locked == nullptr);
}

TEST_CASE("Subscription: Different payload sizes -> All handled correctly") {
    auto subscriber = std::make_shared<MockSubscriber>();

    std::vector<size_t> sizes = {0, 1, 16, 256, 1024, 65536};

    for (size_t size : sizes) {
        std::string payload(size, 'X');
        subscriber->dispatch_packet(to_buffer(payload), "test.subject", {});
    }

    REQUIRE(subscriber->message_count == sizes.size());
}

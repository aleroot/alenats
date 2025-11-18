#include "test_helpers.h"
#include <algorithm>
#include <vector>

using namespace TestHelpers;

// ============================================================================
// STRUCT TESTS
// ============================================================================

TEST_CASE("Cluster: ServerAddress - Comparison -> Works as expected") {
    Nats::ServerAddress s1{"localhost", "4222"};
    Nats::ServerAddress s2{"localhost", "4222"};
    Nats::ServerAddress s3{"other", "4222"};
    Nats::ServerAddress s4{"localhost", "5222"};

    REQUIRE(s1 == s2);
    REQUIRE(s1 != s3);
    REQUIRE(s1 != s4);
    REQUIRE((s1 < s3 || s3 < s1));
}

TEST_CASE("Cluster: ServerAddress - Sorting -> Produces canonical order") {
    std::vector<Nats::ServerAddress> list1 = {
        {"server-b", "4222"},
        {"server-a", "4222"},
        {"server-c", "4222"}
    };

    std::vector<Nats::ServerAddress> list2 = {
        {"server-c", "4222"},
        {"server-b", "4222"},
        {"server-a", "4222"}
    };

    std::ranges::sort(list1);
    std::ranges::sort(list2);
    REQUIRE(list1.size() == list2.size());
    for(size_t i=0; i<list1.size(); i++) {
        REQUIRE(list1[i] == list2[i]);
    }
}

// ============================================================================
// MANAGER TESTS
// ============================================================================

TEST_CASE("Cluster: ConnectionManager - Seed Permutations -> Returns SAME connection") {
    asio::io_context ioc;
    auto mgr = std::make_shared<Nats::ConnectionManager>(ioc);

    std::vector<Nats::ServerAddress> seeds_order_1 = {
        {"192.168.1.10", "4222"},
        {"192.168.1.20", "4222"}
    };

    std::vector<Nats::ServerAddress> seeds_order_2 = {
        {"192.168.1.20", "4222"},
        {"192.168.1.10", "4222"}
    };

    std::shared_ptr<Nats::Connection> conn1;
    std::shared_ptr<Nats::Connection> conn2;

    mgr->async_get_connection(seeds_order_1, std::nullopt, false, [&](auto c) {
        conn1 = c;
    });

    mgr->async_get_connection(seeds_order_2, std::nullopt, false, [&](auto c) {
        conn2 = c;
    });

    run_io_context_for(ioc, std::chrono::milliseconds(50));

    REQUIRE(conn1 != nullptr);
    REQUIRE(conn2 != nullptr);
    REQUIRE(conn1.get() == conn2.get());
}

TEST_CASE("Cluster: ConnectionManager - Subset vs Superset -> Returns DIFFERENT connections") {
    asio::io_context ioc;
    auto mgr = std::make_shared<Nats::ConnectionManager>(ioc);

    std::vector<Nats::ServerAddress> cluster_small = {
        {"server-a", "4222"}
    };

    std::vector<Nats::ServerAddress> cluster_large = {
        {"server-a", "4222"},
        {"server-b", "4222"}
    };

    std::shared_ptr<Nats::Connection> conn1;
    std::shared_ptr<Nats::Connection> conn2;

    mgr->async_get_connection(cluster_small, std::nullopt, false, [&](auto c) { conn1 = c; });
    mgr->async_get_connection(cluster_large, std::nullopt, false, [&](auto c) { conn2 = c; });

    run_io_context_for(ioc, std::chrono::milliseconds(50));

    REQUIRE(conn1 != nullptr);
    REQUIRE(conn2 != nullptr);
    REQUIRE(conn1.get() != conn2.get());
}

TEST_CASE("Cluster: ConnectionManager - Empty Seed List -> Returns nullptr immediately") {
    asio::io_context ioc;
    auto mgr = std::make_shared<Nats::ConnectionManager>(ioc);

    bool callback_invoked = false;
    std::shared_ptr<Nats::Connection> result_conn;

    mgr->async_get_connection(
        std::vector<Nats::ServerAddress>{}, // Empty list
        std::nullopt,
        false,
        [&](std::shared_ptr<Nats::Connection> conn) {
            callback_invoked = true;
            result_conn = conn;
        }
    );

    // Should return immediately via post
    run_io_context_for(ioc, std::chrono::milliseconds(50));

    REQUIRE(callback_invoked);
    REQUIRE(result_conn == nullptr);
}
#include "test_helpers.h"

using namespace TestHelpers;

TEST_CASE("Utils: view_string - Happy Path -> Views content correctly") {
    std::string original = "Hello World";
    auto buffer = to_buffer(original);
    std::string_view view = Nats::view_string(buffer);

    REQUIRE(view == original);
    REQUIRE(view.size() == original.size());
}

TEST_CASE("Utils: view_string - Empty Buffer -> Returns empty view") {
    Nats::Buffer empty_buf;
    std::string_view view = Nats::view_string(empty_buf);

    REQUIRE(view.empty());
}

TEST_CASE("TestHelpers: to_string - Integration -> Converts correctly") {
    auto buffer = to_buffer("Test String");
    std::string result = TestHelpers::to_string(buffer);
    REQUIRE(result == "Test String");
}
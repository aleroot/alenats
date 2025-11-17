# Testing Guide for AleNats

This document explains how to run and write tests for AleNats.

## Quick Start

```bash
# Build with tests enabled
cmake -B build -DASIO_STANDALONE=ON -DBUILD_TESTS=ON
cmake --build build

# Run all tests
./build/tests/alenats_tests

# Run specific tests
./build/tests/alenats_tests "ConnectionPool*"

# Run with verbose output
./build/tests/alenats_tests -v high

# List all available tests
./build/tests/alenats_tests --list-tests
```

## Test Organization

Tests are organized in `tests/` directory:

```
tests/
├── test_main.cpp                 # Catch2 entry point
├── test_helpers.h                # Shared test utilities
├── connection_pool_test.cpp      # ConnectionPool template tests
├── connection_manager_test.cpp   # ConnectionManager tests
└── subscription_test.cpp         # Subscription interface tests
```

## Writing Tests

### Test Structure

Follow the naming convention:
```cpp
TEST_CASE("Component: Action - Condition -> Expected Result") {
    // Arrange
    auto subscriber = std::make_shared<MockSubscriber>();
    
    // Act
    subscriber->dispatch_packet(buffer, "test.subject", headers);
    
    // Assert
    REQUIRE(subscriber->message_count == 1);
    REQUIRE(subscriber->last_subject == "test.subject");
}
```

### Test Categories

Every feature should have tests in all four categories:

#### 1. Happy Path
```cpp
TEST_CASE("ConnectionManager: async_get_connection - No auth -> Creates connection") {
    // Valid inputs, expected behavior
}
```

#### 2. Unhappy Path
```cpp
TEST_CASE("ConnectionManager: async_get_connection - Empty host -> Fails gracefully") {
    // Invalid inputs, error handling
}
```

#### 3. Edge Cases
```cpp
TEST_CASE("Subscription: Large payload (1MB) -> Handled correctly") {
    // Boundary conditions
}
```

#### 4. Negative Tests
```cpp
TEST_CASE("ConnectionPool: Concurrent requests -> All callbacks invoked") {
    // Stress, concurrency, resource cleanup
}
```

### Using Test Helpers

```cpp
#include "test_helpers.h"

using namespace TestHelpers;

// Convert string to buffer
auto buffer = to_buffer("Hello, NATS!");

// Convert buffer back to string
std::string str = to_string(buffer);

// Mock subscriber
auto sub = std::make_shared<MockSubscriber>();
sub->dispatch_packet(buffer, "subject", {});
REQUIRE(sub->message_count == 1);

// Run io_context with timeout
asio::io_context ioc;
run_io_context_for(ioc, std::chrono::milliseconds(100));
```

## Coverage Reports

Generate HTML coverage report:

```bash
# Build with coverage enabled
cmake -B build -DASIO_STANDALONE=ON -DBUILD_TESTS=ON -DENABLE_COVERAGE=ON
cmake --build build

# Run tests
./build/tests/alenats_tests

# Generate report
lcov --capture --directory build --output-file coverage.info
lcov --remove coverage.info '/usr/*' '*/build/_deps/*' '*/tests/*' --output-file coverage.filtered.info
genhtml coverage.filtered.info --output-directory coverage_report

# View in browser
open coverage_report/index.html
```

## Continuous Integration

Tests run automatically on:
- All pushes to `main` and `develop`
- All pull requests

**Build matrix:**
- Ubuntu: GCC 13, Clang 16
- macOS: AppleClang
- Both Boost.Asio and standalone Asio variants

**Coverage requirements:**
- Minimum: 70% line coverage
- Target: 85%+ for core components

## Known Limitations

### Async Testing Challenges

Testing async code requires careful timing:

```cpp
// Run io_context for limited time
run_io_context_for(ioc, std::chrono::milliseconds(500));

// Longer timeout for slow operations
run_io_context_for(ioc, std::chrono::milliseconds(2000));
```

### Commented Out Tests

Some tests are commented out because they reveal real library issues:

1. **ConnectionManager lifetime issue:** Use-after-free when destroyed with pending ops
2. **ConnectionPool timing issue:** Multiple connections created in rapid concurrent requests

These are documented in the test files and should be addressed in future library improvements.

## Debugging Failed Tests

### Run single test
```bash
./build/tests/alenats_tests "ConnectionManager: async_get_connection - Empty host"
```

### Enable verbose logging
```cpp
// In your test
Nats::logger.info = [](std::string_view msg) {
    std::println("INFO: {}", msg);
};
Nats::logger.error = [](std::string_view msg) {
    std::println(std::cerr, "ERROR: {}", msg);
};
```

### Use debugger
```bash
lldb ./build/tests/alenats_tests
(lldb) run "ConnectionManager*"
```

## Contributing Tests

When adding a new feature:

1. Write failing tests first (TDD)
2. Cover all four categories (happy, unhappy, edge, negative)
3. Ensure tests pass locally
4. Check coverage hasn't dropped
5. Update this document if adding new test patterns

See `CONTRIBUTING.md` for full contribution guidelines.

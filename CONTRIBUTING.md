# Contributing to AleNats

Thank you for considering contributing to AleNats! This document provides guidelines and standards for contributing to this project.

## Table of Contents

- [Development Environment](#development-environment)
- [Development Workflow](#development-workflow)
- [Code Standards](#code-standards)
- [Testing Standards](#testing-standards)
- [Pull Request Process](#pull-request-process)
- [Architecture Decisions](#architecture-decisions)

## Development Environment

### Prerequisites

**Required:**
- C++23 compatible compiler (GCC 13+, Clang 16+, or MSVC 19.35+)
- CMake 3.22+
- OpenSSL 3.0+
- Either Boost 1.89.0+ or standalone Asio

**Recommended development tools:**
- `clang-format` - Code formatting (auto-installed by pre-commit hook)
- `clang-tidy` - Static analysis
- `gcov`/`lcov` - Code coverage reporting
- `valgrind` or `AddressSanitizer` - Memory leak detection

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/bjcoombs/alenats.git
cd alenats

# Build with standalone Asio (recommended for development)
cmake -B build -DASIO_STANDALONE=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build

# Run tests
./build/tests/alenats_tests

# Run examples
./build/examples/subscribe &
./build/examples/publish
```

### Installing Pre-commit Hooks

We use pre-commit hooks to ensure code quality before commits:

```bash
# Install hooks
cp .githooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

The pre-commit hook will:
- Run `clang-format` on all staged C++ files
- Run basic build checks
- Ensure no trailing whitespace or debug prints

## Development Workflow

### Branch Strategy

We follow a standard Git flow:

1. **`main`** - Stable releases only
2. **`develop`** - Integration branch for features
3. **`feature/*`** - Individual feature branches
4. **`fix/*`** - Bug fix branches

### Creating a Feature Branch

```bash
# Update develop
git checkout develop
git pull origin develop

# Create feature branch
git checkout -b feature/my-new-feature

# Make changes, commit, push
git add .
git commit -m "feat: Add support for JetStream"
git push origin feature/my-new-feature
```

### Commit Message Format

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>: <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `refactor`: Code restructuring without behavior change
- `test`: Adding or updating tests
- `docs`: Documentation changes
- `chore`: Build system, dependencies, tooling
- `perf`: Performance improvements

**Examples:**
```
feat: Add JetStream consumer support

fix: Prevent race condition in connection pool cleanup

test: Add unhappy path tests for NKEY authentication

refactor: Extract protocol parser into separate component
```

**Guidelines:**
- Use imperative mood ("Add feature" not "Added feature")
- Keep first line under 72 characters
- Provide context in the body for complex changes
- Reference issues: "Fixes #123" or "Relates to #456"

## Code Standards

### C++ Style Guidelines

**Language Features:**
- Modern C++23 idioms (coroutines, ranges, concepts where appropriate)
- RAII for resource management
- `std::expected` or callback patterns for error handling
- `const` correctness
- Smart pointers (`std::shared_ptr`, `std::weak_ptr`, `std::unique_ptr`)

**Naming Conventions:**
```cpp
namespace Nats {
    // PascalCase for types
    class ConnectionManager { };
    struct Credentials { };
    enum class ClientState { };

    // camelCase for functions/methods
    void async_publish(...);
    auto get_connection() -> std::shared_ptr<Connection>;

    // lowercase_with_underscores for variables
    int retry_count = 0;
    std::string server_address;

    // SCREAMING_SNAKE_CASE for constants
    constexpr int MAX_RECONNECT_ATTEMPTS = 5;
}
```

**File Organization:**
```cpp
// alenats.h - Public interface (header-plus-implementation pattern)
// alenats.cpp - Implementation details

// Co-located tests
// tests/connection_test.cpp
// tests/subscription_test.cpp
// tests/protocol_parser_test.cpp
```

**Formatting:**
- 4-space indentation (no tabs)
- Opening braces on same line
- Max line length: 120 characters
- Use `clang-format` (configuration provided in `.clang-format`)

### Thread Safety

**Critical:** AleNats is designed for multi-threaded environments using Asio strands:

```cpp
// CORRECT: All connection state modifications must use the connection's strand
asio::post(connection->get_executor(), [this, conn] {
    // Safe to modify connection state here
    conn->internal_state_change();
});

// INCORRECT: Direct modification from arbitrary threads
connection->internal_state_change();  // RACE CONDITION!
```

**Rules:**
1. All mutable state must be protected by a strand or mutex
2. `ConnectionPool` uses strand-based serialization
3. Never hold locks across async operation boundaries
4. Document thread-safety guarantees in class comments

### Error Handling

**Pattern:**
```cpp
// For async operations: callback with success/error
void async_publish(
    std::string_view subject,
    Headers headers,
    Buffer payload,
    std::function<void(bool success, std::string_view error)> handler
);

// For synchronous operations: std::expected (C++23)
auto parse_credentials(std::string_view data)
    -> std::expected<Credentials, std::string>;
```

**Never:**
- Throw exceptions across async boundaries
- Silently ignore errors (log at minimum)
- Use error codes without context messages

### Resource Management

**RAII everywhere:**
```cpp
// Subscriptions automatically cleanup via weak_ptr
class MySubscriber : public Nats::Subscription {
    // When this object is destroyed, subscription is removed
};

// Connections cleanup when all shared_ptr references are released
{
    auto conn = conn_mgr->get_connection(...);
    // Use connection
} // Connection may be returned to pool or destroyed
```

## Testing Standards

### Test-Driven Development (TDD)

We follow **Red-Green-Refactor** cycle:

1. **Red:** Write a failing test that describes desired behavior
2. **Green:** Implement minimal code to make the test pass
3. **Refactor:** Improve code quality without changing behavior

**Example:**
```cpp
// RED: Write failing test
TEST_CASE("ConnectionManager returns same connection for identical destinations") {
    // Test fails because feature doesn't exist yet
}

// GREEN: Implement feature
// ... add connection pooling logic ...

// REFACTOR: Clean up implementation
// ... extract functions, improve naming, add comments ...
```

### Test Categories

Following Meridian's defensive testing approach, all features must have:

#### 1. Happy Path Tests
Valid inputs, expected behavior:
```cpp
TEST_CASE("Connection publishes message successfully") {
    auto conn = get_test_connection();
    bool success = false;

    conn->async_publish("test.subject", {}, to_buffer("Hello"),
        [&](bool ok, auto) { success = ok; });

    run_until_complete();
    REQUIRE(success);
}
```

#### 2. Unhappy Path Tests
Invalid inputs, graceful failure:
```cpp
TEST_CASE("Connection rejects publish with empty subject") {
    auto conn = get_test_connection();
    bool failed = false;

    conn->async_publish("", {}, to_buffer("Hello"),
        [&](bool ok, auto err) {
            failed = !ok;
            REQUIRE(err.find("subject") != std::string::npos);
        });

    run_until_complete();
    REQUIRE(failed);
}
```

#### 3. Edge Cases
Boundary conditions:
```cpp
TEST_CASE("Connection handles maximum message size") {
    auto conn = get_test_connection();
    auto large_payload = create_payload(MAX_PAYLOAD_SIZE);

    // Should succeed at exact limit
    bool success = false;
    conn->async_publish("test", {}, large_payload,
        [&](bool ok, auto) { success = ok; });

    run_until_complete();
    REQUIRE(success);
}

TEST_CASE("Connection rejects message exceeding maximum size") {
    auto conn = get_test_connection();
    auto oversized = create_payload(MAX_PAYLOAD_SIZE + 1);

    bool failed = false;
    conn->async_publish("test", {}, oversized,
        [&](bool ok, auto err) {
            failed = !ok;
            REQUIRE(err.find("too large") != std::string::npos);
        });

    run_until_complete();
    REQUIRE(failed);
}
```

#### 4. Negative Tests
Conditions that shouldn't occur:
```cpp
TEST_CASE("Connection detects protocol violations") {
    auto conn = get_test_connection();

    // Simulate malformed server response
    inject_malformed_response(conn, "INVALID PROTOCOL");

    // Connection should enter error state
    REQUIRE(conn->get_state() == ClientState::ERROR);
}

TEST_CASE("Subscription handles concurrent unsubscribe") {
    auto sub = create_subscriber();
    auto conn = get_test_connection();

    conn->subscribe("test", sub);

    // Simulate concurrent unsubscribe + message delivery
    std::thread t1([&] { conn->unsubscribe("test"); });
    std::thread t2([&] { simulate_message_delivery(conn, "test"); });

    t1.join();
    t2.join();

    // Should not crash or deadlock
    REQUIRE(true);
}
```

### Test Organization

**File Structure:**
```
tests/
├── CMakeLists.txt
├── test_main.cpp                 # Catch2 main entry point
├── connection_test.cpp           # Connection interface tests
├── connection_manager_test.cpp   # Connection pooling tests
├── subscription_test.cpp         # Subscription lifecycle tests
├── protocol_parser_test.cpp      # NATS protocol parsing
├── authentication_test.cpp       # Auth mechanisms (NKEY, token, etc.)
└── test_helpers.h                # Shared test utilities
```

**Test Naming Convention:**
```cpp
// Format: TEST_CASE("Component: Action - Condition -> Expected Result")

TEST_CASE("ConnectionManager: get_connection - Same destination -> Returns pooled connection") { }
TEST_CASE("ConnectionManager: get_connection - Different auth -> Returns new connection") { }
TEST_CASE("Connection: async_publish - Empty subject -> Fails with error") { }
TEST_CASE("Subscription: dispatch_packet - Subscriber destroyed -> No crash") { }
```

### Running Tests

```bash
# Run all tests
./build/tests/alenats_tests

# Run specific test
./build/tests/alenats_tests "ConnectionManager*"

# Run with verbose output
./build/tests/alenats_tests -v high

# Generate coverage report
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DENABLE_COVERAGE=ON
cmake --build build
./build/tests/alenats_tests
lcov --capture --directory build --output-file coverage.info
lcov --remove coverage.info '/usr/*' '*/build/_deps/*' --output-file coverage.filtered.info
genhtml coverage.filtered.info --output-directory coverage_report
```

### Coverage Requirements

- **Minimum threshold:** 70% line coverage (excluding external dependencies)
- **Target:** 85%+ for core components (Connection, ConnectionManager, protocol parsing)
- **Exclusions:** Generated code, external dependencies (simdjson, Asio, OpenSSL)

Focus coverage on:
1. Error handling paths
2. State transitions
3. Concurrent access patterns
4. Resource cleanup (RAII)

## Pull Request Process

### Before Submitting

**Checklist:**
- [ ] All tests pass locally
- [ ] New tests added for new features/fixes
- [ ] Code formatted with `clang-format`
- [ ] No compiler warnings (`-Wall -Wextra -Werror`)
- [ ] Documentation updated (README, code comments)
- [ ] Commit messages follow conventional format
- [ ] PR description explains **why**, not just **what**

### PR Description Template

```markdown
## Summary
Brief description of the change and motivation.

## Changes Made
- Bullet list of specific changes
- Focus on behavior, not implementation details

## Testing
- Describe test coverage
- Mention edge cases tested
- Include any manual testing performed

## Performance Considerations
- Any performance impacts (positive or negative)
- Benchmarks if applicable

## Breaking Changes
- List any API changes
- Migration path for users

## Related Issues
Fixes #123
Relates to #456
```

### Review Process

1. **Automated checks** must pass:
   - Build on Ubuntu (GCC, Clang)
   - Build on macOS (AppleClang)
   - All tests pass
   - Code coverage threshold met
   - No security vulnerabilities (static analysis)

2. **Peer review:**
   - At least one maintainer approval required
   - Address all review comments or provide rationale
   - Re-request review after changes

3. **Merge:**
   - Squash commits for clean history (maintainers will handle)
   - Delete feature branch after merge

## Architecture Decisions

### Recording Decisions

For significant architectural choices, create an Architecture Decision Record (ADR) in `docs/adr/`:

```bash
# Create new ADR
mkdir -p docs/adr
cat > docs/adr/0001-use-header-plus-implementation-pattern.md <<EOF
# ADR 0001: Use Header-Plus-Implementation Pattern

## Status
Accepted

## Context
We need to decide on library distribution model...

## Decision
Use header-plus-implementation pattern (alenats.h + alenats.cpp)...

## Consequences
- Easier integration (no complex build requirements)
- Faster compilation (not header-only)
- Clear API boundary
EOF
```

**Format:**
1. **Status:** Proposed | Accepted | Deprecated | Superseded
2. **Context:** What forces are at play?
3. **Decision:** What did we decide?
4. **Consequences:** What are the trade-offs?

### When to Create an ADR

- New architectural patterns
- Technology choices (libraries, frameworks)
- API design decisions
- Performance trade-offs
- Security considerations

## Getting Help

- **Issues:** Open a GitHub issue for bugs or feature requests
- **Discussions:** Use GitHub Discussions for questions
- **Security:** Report security issues privately to maintainers

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Assume good intentions
- Professional technical communication

---

**Questions about contributing?** Open a GitHub Discussion or reach out to maintainers.

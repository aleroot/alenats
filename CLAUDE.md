# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AleNats is a high-performance, asynchronous NATS client for C++23, built on Asio and C++ coroutines. It's a header-plus-implementation library (alenats.h + alenats.cpp) designed for minimal integration overhead.

**Key Design Principles:**
- Uses C++23 coroutines for async operations
- Compatible with both Boost.Asio and standalone Asio (via CMake option)
- Connection pooling and automatic reconnection via `ConnectionManager`
- Thread-safe operations using Asio strands
- Minimal dependencies: Asio, OpenSSL 3.0+, simdjson

## Architecture Decision Records (ADRs)

**IMPORTANT:** Before proposing significant changes, consult the ADR directory.

ADRs document both what we chose AND what we rejected (with reasoning):
- **Location:** `docs/adr/`
- **Index:** See `docs/adr/README.md` for complete catalog
- **Format:** YAML frontmatter with tags for searchability

**When to reference ADRs:**
- Proposing alternative libraries or frameworks
- Questioning existing architectural choices
- Before re-evaluating rejected alternatives
- Understanding context behind technical decisions

**Current ADRs:**
- [ADR-0001: Testing Infrastructure](docs/adr/0001-testing-infrastructure.md)
  - Tags: testing, ci-cd, quality, catch2
  - Documents why Catch2 was chosen over Google Test, Boost.Test, doctest
  - Explains testing philosophy and coverage requirements

**Quick ADR search:**
```bash
# Find ADRs by tag
grep -r "tags:.*testing" docs/adr/

# List all accepted decisions
grep -l "status: accepted" docs/adr/*.md
```

## Build Commands

### Basic Build (with standalone Asio)
```bash
cmake -B build -DASIO_STANDALONE=ON
cmake --build build
```

### Build with Boost.Asio (default)
```bash
cmake -B build
cmake --build build
```

### Build with specific C++ compiler
```bash
cmake -B build -DCMAKE_CXX_COMPILER=g++-13 -DASIO_STANDALONE=ON
cmake --build build
```

### Run Examples
```bash
./build/examples/subscribe
./build/examples/publish
```

## Architecture

### Core Components

**ConnectionManager** (alenats.h:289-312, alenats.cpp)
- Entry point for obtaining connections
- Manages connection pooling using `ConnectionPool<Connection>`
- Ensures one connection per unique destination (host:port:auth:ssl)
- Thread-safe via Asio strand

**Connection Interface** (alenats.h:133-185)
- Pure virtual interface for NATS operations
- Key methods: `subscribe()`, `unsubscribe()`, `async_publish()`
- State tracking via `ClientState` enum
- Provides executor access for scheduling operations

**Subscription Interface** (alenats.h:112-127)
- Implement this to receive messages
- Uses weak_ptr for automatic cleanup when subscribers are destroyed
- `dispatch_packet()` receives payload, subject, and headers

**ConnectionPool<T>** (alenats.h:196-280)
- Generic connection pooling template
- Thread-safe get-or-create pattern using Asio strand
- Stores weak_ptr to allow automatic cleanup
- Factory function pattern for creating connections

### Implementation Details (alenats.cpp)

**NATS Protocol Implementation:**
- Custom NKEY authentication with Ed25519 signatures (Nats::Crypto namespace)
- Base64URL encoding for NATS signatures (no padding)
- Base32 decoding for NKEY seeds
- Supports username/password, token, and NKEY auth

**Async I/O:**
- Uses Asio coroutines (`asio::awaitable`) for connection handling
- Strand-based serialization for thread safety
- SSL/TLS support via OpenSSL
- Automatic reconnection with exponential backoff

**Message Parsing:**
- simdjson for parsing NATS INFO messages
- Custom protocol parser for MSG/HMSG/PING/PONG/ERR

## Asio Compatibility Layer

The library uses conditional compilation to support both Boost.Asio and standalone Asio:

```cpp
#ifdef ASIO_STANDALONE
    #include <asio/io_context.hpp>
    // ...
#else
    #include <boost/asio/io_context.hpp>
    namespace asio = boost::asio;
#endif
```

When modifying code that uses Asio types, ensure both paths are maintained.

## Testing Approach

No formal test suite exists currently. Testing is done via the examples:

- `examples/subscribe.cpp`: Demonstrates subscription handling
- `examples/publish.cpp`: Demonstrates message publishing with headers

To test changes:
1. Build the examples
2. Run subscribe in one terminal: `./build/examples/subscribe`
3. Run publish in another: `./build/examples/publish`
4. Verify messages are received correctly

## Common Development Tasks

### Adding New NATS Features

1. **Check ADRs first** - See if related architectural decisions exist
2. Update the `Connection` interface in alenats.h (pure virtual methods)
3. Implement in the concrete class (likely `NatsConnection` in alenats.cpp)
4. Ensure thread-safety using the connection's strand
5. **Write tests** - Follow TDD approach (see TESTING.md)
6. Update examples to demonstrate the feature
7. **Consider an ADR** - If the feature involves significant choices or tradeoffs

### Modifying Authentication

- NKEY crypto logic: `Nats::Crypto` namespace in alenats.cpp
- Credentials struct: alenats.h:57-62
- Authentication handshake: Search for "CONNECT" command in alenats.cpp

### Debugging Connection Issues

Enable the built-in logger:
```cpp
Nats::logger.info = [](std::string_view msg) {
    std::println("INFO: {}", msg);
};
Nats::logger.error = [](std::string_view msg) {
    std::println(std::cerr, "ERROR: {}", msg);
};
```

Or use the `PRINT_LOG()` utility function (alenats.h:93-95).

## CMake Integration Patterns

The library is designed to be consumed via:

1. **FetchContent** (recommended for new projects)
2. **Git submodule** + `add_subdirectory()`
3. **Direct source inclusion**

The exported target is `alenats::alenats` and automatically links dependencies (simdjson, OpenSSL, Asio).

## Code Style

- C++23 standard features are expected (coroutines, std::print, std::format)
- Use `Nats::Buffer` (alias for `std::vector<std::byte>`) for message payloads
- Prefer `std::weak_ptr<Subscription>` for subscriber lifetime management
- Use Asio strands for serializing access to shared state
- Handler callbacks follow the pattern: `std::function<void(bool success, std::string_view error)>`

## Dependencies to Track

- **simdjson**: FetchContent at v4.2.2 (CMakeLists.txt:12-17)
- **Asio**: FetchContent at asio-1-36-0 when standalone (CMakeLists.txt:21-26)
- **Boost**: version 1.89.0+ when using Boost.Asio (CMakeLists.txt:29)
- **OpenSSL**: 3.0+ required for SSL/TLS and NKEY signatures
- **Catch2**: v3.7.1 for testing (tests/CMakeLists.txt)

When updating dependencies, ensure compatibility with both Asio variants.

**Note:** If proposing a new dependency, consider creating an ADR documenting:
- Why it's needed
- What alternatives were evaluated
- The tradeoffs involved
- Impact on build time and binary size

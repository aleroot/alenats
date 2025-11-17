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
- C++23 compatible compiler (GCC 14+, Clang 17+, or MSVC 19.35+)
- CMake 3.22+
- OpenSSL 3.0+
- Either Boost 1.89.0+ or standalone Asio

### Initial Setup

#### Ubuntu/Debian

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y cmake ninja-build libssl-dev g++-14

# Clone the repository
git clone https://github.com/aleroot/alenats.git
cd alenats

# Build with standalone Asio (recommended for development)
cmake -B build -G Ninja -DCMAKE_CXX_COMPILER=g++-14 \
    -DASIO_STANDALONE=ON -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON
cmake --build build

# Run tests
./build/tests/alenats_tests

# Run examples
./build/examples/subscribe &
./build/examples/publish
```

#### OpenSUSE (Tumbleweed/Leap)

```bash
# Install dependencies
sudo zypper install -y cmake ninja gcc13 gcc13-c++ libopenssl-3-devel

# For Boost.Asio variant (optional)
sudo zypper install -y boost-devel

# Clone the repository
git clone https://github.com/aleroot/alenats.git
cd alenats

# Build with standalone Asio
cmake -B build -G Ninja -DCMAKE_CXX_COMPILER=g++-14 \
    -DASIO_STANDALONE=ON -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON
cmake --build build

# Run tests
./build/tests/alenats_tests

# Run examples
./build/examples/subscribe &
./build/examples/publish
```

#### macOS

```bash
# Install dependencies
brew install cmake ninja openssl@3

# Clone the repository
git clone https://github.com/aleroot/alenats.git
cd alenats

# Build with standalone Asio
cmake -B build -G Ninja \
    -DASIO_STANDALONE=ON -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON \
    -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
cmake --build build

# Run tests
./build/tests/alenats_tests

# Run examples
./build/examples/subscribe &
./build/examples/publish
```

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

## Code Standards

### C++ Style Guidelines

**Language Features:**
- Modern C++23 idioms (coroutines, ranges, concepts where appropriate)
- RAII for resource management
- `std::expected` or callback patterns for error handling
- `const` correctness
- Smart pointers (`std::shared_ptr`, `std::weak_ptr`, `std::unique_ptr`)


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

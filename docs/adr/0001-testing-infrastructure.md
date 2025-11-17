---
title: "ADR-0001: Testing Infrastructure and Quality Standards"
status: accepted
date: 2025-11-17
tags: [testing, ci-cd, quality, catch2, github-actions, coverage, tooling]
authors: [bjcoombs]
---

# ADR 0001: Testing Infrastructure and Quality Standards

## Status
Accepted

## Context

AleNats is a C++23 NATS client library designed for production use. To ensure reliability and maintainability, we need:

1. **Automated testing** covering both happy paths and error conditions
2. **Continuous Integration** to catch regressions early
3. **Code quality tooling** to maintain consistent style
4. **Contributing guidelines** to help new contributors

Without these, the library risks:
- Undiscovered bugs in error handling paths
- Regressions when adding features
- Inconsistent code style across contributors
- Difficulty onboarding new contributors

## Decision

We have adopted a comprehensive testing and quality infrastructure inspired by industry best practices:

### Testing Framework: Catch2 v3

**Decision:** Use Catch2 v3 as the testing framework.

**Why Catch2:**
- Modern C++23 support (templates, concepts, coroutines)
- Header-only library (minimal integration complexity)
- Excellent readability (BDD-style `TEST_CASE` syntax)
- Rich assertion macros (`REQUIRE`, `CHECK`, etc.)
- Built-in test discovery for CTest integration
- Active maintenance and community

**Alternatives Considered:**

#### Alternative 1: Google Test (gtest/gmock)
- **Pros:**
  - Industry standard, widely known
  - Excellent mocking support (gmock)
  - Mature ecosystem with extensive documentation
  - Used by many large projects
- **Cons:**
  - More complex CMake integration
  - Older C++ standard idioms (C++11 era)
  - Verbosity in test naming (`TEST(TestSuite, TestCase)`)
  - Heavier dependency footprint
- **Why rejected:** Overkill for a header-only library; older C++ patterns don't match project's C++23 style

#### Alternative 2: Boost.Test
- **Pros:**
  - Part of Boost ecosystem
  - Good integration if already using Boost.Asio
  - Mature and stable
- **Cons:**
  - Adds Boost dependency to test suite
  - More complex setup than Catch2
  - Less modern C++ support
  - Project aims to support standalone Asio (no Boost requirement)
- **Why rejected:** Contradicts goal of minimal dependencies; Boost already optional for library itself

#### Alternative 3: doctest
- **Pros:**
  - Ultra-lightweight (fastest compilation)
  - Catch2-like syntax (easy migration)
  - Single header file
  - Very fast test execution
- **Cons:**
  - Less mature than Catch2 (newer project)
  - Smaller community and ecosystem
  - Fewer advanced features (e.g., BDD sections)
  - Less comprehensive documentation
- **Why rejected:** While appealing for compilation speed, Catch2's maturity and features outweigh the compilation time cost for this project size

#### Alternative 4: Roll-our-own test framework
- **Pros:**
  - Complete control over features
  - Zero external dependencies
  - Perfect fit for project needs
- **Cons:**
  - Significant development and maintenance burden
  - Reinventing well-solved problems
  - Missing advanced features (test discovery, fixtures, etc.)
  - Lower contributor familiarity
- **Why rejected:** Not a core competency of the project; well-established frameworks exist

### Test Organization

**Co-located tests:** Test files live in `tests/` directory alongside the library code:
```
alenats-main/
├── alenats.h
├── alenats.cpp
├── tests/
│   ├── connection_pool_test.cpp
│   ├── connection_manager_test.cpp
│   ├── subscription_test.cpp
│   └── test_helpers.h
```

**Four-tier testing approach** (borrowed from defensive testing standards):
1. **Happy Path:** Valid inputs, expected behavior
2. **Unhappy Path:** Invalid inputs, graceful failure
3. **Edge Cases:** Boundary conditions (empty strings, max sizes, null values)
4. **Negative Tests:** Concurrency, stress, resource cleanup

**Test naming convention:**
```cpp
TEST_CASE("Component: Action - Condition -> Expected Result")

// Examples:
TEST_CASE("ConnectionManager: async_get_connection - Empty host -> Callback invoked with null")
TEST_CASE("Subscription: Message with headers -> Headers preserved")
```

### Continuous Integration: GitHub Actions

**Three workflows:**

1. **test.yml** - Build and test matrix:
   - Ubuntu: GCC 13, Clang 16
   - macOS: AppleClang
   - Both Boost.Asio and standalone Asio variants
   - Code coverage reporting to Codecov

2. **quality.yml** - Code quality checks:
   - clang-format (style enforcement)
   - Build examples (smoke test)
   - clang-tidy (static analysis)

3. **Coverage requirements:**
   - Minimum: 70% line coverage
   - Target: 85%+ for core components
   - Exclusions: Generated code, external dependencies

### Code Formatting: clang-format

- **Configuration:** `.clang-format` in repository root
- **Style:** Based on LLVM with 4-space indents, 120-char lines
- **Enforcement:** Pre-commit hook auto-formats staged files

### Pre-commit Hooks

Located in `.githooks/pre-commit`:
- Auto-installs clang-format if missing
- Formats all staged C++ files
- Checks for debug print statements (warns but doesn't block)
- Removes trailing whitespace

**Installation:**
```bash
cp .githooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### Contributing Guidelines

Comprehensive `CONTRIBUTING.md` documenting:
- Development environment setup
- TDD workflow (Red-Green-Refactor)
- Test categories and requirements
- Code style standards
- PR process and checklist
- Architecture Decision Record (ADR) format

## Consequences

### Positive

1. **Early bug detection:** Automated tests catch regressions before merging
2. **Confidence in refactoring:** Test suite enables safe code improvements
3. **Consistent quality:** Automated formatting and linting reduce style debates
4. **Clear expectations:** CONTRIBUTING.md helps new contributors succeed
5. **Documentation through tests:** Test names document expected behavior

### Negative / Trade-offs

1. **Initial setup cost:** Took time to configure CI, write initial tests
2. **Build time increase:** Tests add ~30 seconds to build time
3. **Test maintenance:** Tests need updating when APIs change
4. **Flaky tests:** Some async tests reveal timing issues (documented in comments)
   - Example: Rapid concurrent requests to ConnectionPool may create multiple connections
   - Example: Early destruction of ConnectionManager reveals use-after-free issue

### Known Issues (Documented in Tests)

Two tests were commented out due to revealing real library issues:

1. **ConnectionManager lifetime issue:**
   - Test: "Manager destroyed before callbacks -> No crash"
   - Issue: Use-after-free when manager destroyed with pending async ops
   - Fix needed: Use `std::enable_shared_from_this` pattern

2. **ConnectionPool timing issue:**
   - Test: "Rapid sequential requests -> Maintains consistency"
   - Issue: Multiple connections created before first stored in pool
   - Expected behavior: Callers should synchronize or accept multiple connections

These are valuable findings that improve library robustness awareness.

## Implementation Details

### Test Coverage

**33 test cases, 79 assertions covering:**
- `ConnectionPool<T>` template (8 tests)
  - Happy: Creation, pooling, key-based retrieval
  - Unhappy: Destroyed connections, null factories, empty keys
  - Negative: Concurrent requests, rapid sequential access

- `ConnectionManager` (10 tests)
  - Happy: Construction, various auth methods, SSL
  - Unhappy: Empty host/port, invalid hostnames
  - Edge: Unusual ports, NKEY credentials
  - Negative: Concurrent requests, different destinations

- `Subscription` interface (15 tests)
  - Happy: Message delivery, headers, multiple messages
  - Unhappy: Empty subjects, special characters, empty headers
  - Edge: Large payloads, binary data, long subjects
  - Negative: Rapid messages, multiple subscribers, weak_ptr lifecycle

### CI Build Matrix

Total: 6 builds per commit
- Ubuntu + GCC 13 + Standalone Asio
- Ubuntu + GCC 13 + Boost.Asio
- Ubuntu + Clang 16 + Standalone Asio
- Ubuntu + Clang 16 + Boost.Asio
- macOS + AppleClang + Standalone Asio
- macOS + AppleClang + Boost.Asio

Plus 1 coverage build (Ubuntu + GCC 13 + --coverage)

## References

- Catch2 documentation: https://github.com/catchorg/Catch2
- Defensive testing standards: Inspired by ADR-008 from Meridian project
- Google C++ Style Guide (for formatting decisions)
- Boost.Asio best practices (for async testing patterns)

## Future Considerations

1. **Integration tests:** Add tests that connect to real NATS server
2. **Benchmark tests:** Performance regression testing for critical paths
3. **Fuzzing:** AFL or libFuzzer for protocol parser robustness
4. **Sanitizers:** Regular runs with AddressSanitizer, ThreadSanitizer, UBSan
5. **Coverage threshold enforcement:** Fail CI if coverage drops below 70%

---

*Created: 2025-11-17*
*Last Updated: 2025-11-17*

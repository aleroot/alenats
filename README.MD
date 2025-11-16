# AleNats - A Modern C++ NATS Client

**AleNats** is a high-performance, asynchronous [NATS](https://github.com/nats-io/nats-server) client for C++23, built on [Asio](https://github.com/chriskohlhoff/asio) and C++ coroutines. It is designed as a minimalistic library for easy integration into any project. It is compatible with both Boost.Asio and Standalone Asio. Uses [simdjson](https://github.com/simdjson/simdjson) for Json parsing during NATS communication.

This library provides a NATS client that supports:
* TCP and TLS (SSL) connections
* Header (HMSG)
* Username/Password, Token, and NKEY authentication
* Automatic reconnect on failure
* Asynchronous publish and subscribe

## Dependencies

AleNats relies on a few high-quality libraries:

1.  **Asio:** either **Boost.Asio** or standalone **Asio**.
2.  **OpenSSL (3.0+):** For SSL/TLS and NKEY cryptographic signatures. (Requires linking `libssl` and `libcrypto`).
3.  **simdjson:** For high-speed JSON parsing. You must make this library available to your build.

## Usage

`alenats` is designed to simple and straightforward. Here are the few core concepts to be aware of.
*(See the `examples/` directory for complete, runnable programs.)*

### 1\. The Connection Manager

The `ConnectionManager` is your entry point. It runs on an `asio::io_context` and handles connection sharing and automatic reconnects.

```cpp
#include "alenats.h"
#include <asio/io_context.hpp>

asio::io_context ioc;
auto conn_mgr = std::make_shared<Nats::ConnectionManager>(ioc);

// Asynchronously request a connection
conn_mgr->async_get_connection(
    "demo.nats.io", "4222",  // Host and Port
    std.nullopt,             // No auth
    false,                   // No SSL
    [&](std::shared_ptr<Nats::Connection> conn) {
        if (conn) {
            // You are now connected!
        }
    }
);
ioc.run();
```

### 2\. Publishing Messages

Publishing is a simple async call on the connection object:

```cpp
std::map<std::string, std::string> headers;
headers["X-My-Header"] = "hello";

conn->async_publish(
    "subject.with.headers",
    std::move(headers),
    Nats::to_buffer("Hello NATS!"),
    [](bool success, std::string_view error) {
        if (success) {
            std::println("Message delivered!");
        }
    }
);
```

### 3\. Subscribing to Messages

To subscribe, implement the `Nats::Subscription` interface and pass a `weak_ptr` to your object.

## Running the Examples

The `examples/` directory provides complete, runnable programs. You can build and run them directly using CMake.

Assuming you are at the root of the `alenats` directory:

```bash
cmake -B build -DASIO_STANDALONE=ON
cmake --build build

./build/examples/subscribe
./build/examples/publish
```

## Integrating with Your Project

You can easily add `alenats` to your existing CMake project. Here are the two simple methods:

### CMake FetchContent

This is the cleanest, most modern CMake approach. It downloads and configures `alenats` automatically at configure-time.

1.  Add these lines to your `CMakeLists.txt`:

    ```cmake
    include(FetchContent)

    FetchContent_Declare(
        alenats
        GIT_REPOSITORY https://github.com/aleroot/alenats.git  
        GIT_TAG        main                                       
    )

    FetchContent_MakeAvailable(alenats)
    ```

2.  Link to your target. The `alenats::alenats` target will automatically bring in its dependencies (Asio, OpenSSL, simdjson).

    ```cmake
    add_executable(my_app main.cpp)
    target_link_libraries(my_app PRIVATE alenats::alenats)
    ```

### Using Git Submodule or Local Copy

If you prefer to include the library as a git submodule or by copying the source into your project (e.g., in a `libs/` folder):

1.  Add the library to your project:

    ```bash
    # Example: Add as a submodule in a 'libs' directory
    git submodule add https://github.com/aleroot/alenats.git libs/alenats
    ```

2.  In your `CMakeLists.txt`, use `add_subdirectory`:

    ```cmake
    # This adds the 'alenats::alenats' target
    add_subdirectory(libs/alenats)

    # ...

    add_executable(my_app main.foo)
    target_link_libraries(my_app PRIVATE alenats::alenats)
    ```
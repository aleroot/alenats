cmake_minimum_required(VERSION 3.22)
project(alenats CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(ASIO_STANDALONE "Build with standalone Asio instead of Boost.Asio" OFF)
option(BUILD_TESTS "Build test suite" OFF)

find_package(OpenSSL REQUIRED)
include(FetchContent)

FetchContent_Declare(
  simdjson
  GIT_REPOSITORY https://github.com/simdjson/simdjson.git
  GIT_TAG v4.2.2
)
FetchContent_MakeAvailable(simdjson)

if(ASIO_STANDALONE)
    message(STATUS "Building alenats with Standalone Asio")
    FetchContent_Declare(
      asio
      GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
      GIT_TAG asio-1-36-0
    )
    FetchContent_MakeAvailable(asio) 
else()
    message(STATUS "Building alenats with Boost.Asio")
    find_package(Boost 1.89.0 REQUIRED COMPONENTS system)
endif()


add_library(alenats alenats.cpp alenats.h)
target_include_directories(alenats PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(alenats
  PUBLIC
    simdjson::simdjson
    OpenSSL::SSL
    OpenSSL::Crypto
)

if(ASIO_STANDALONE)
    target_compile_definitions(alenats PUBLIC ASIO_STANDALONE)
    target_include_directories(alenats PUBLIC
      ${asio_SOURCE_DIR}/asio/include
    )
else()
    target_include_directories(alenats PUBLIC ${Boost_INCLUDE_DIRS})
    target_link_libraries(alenats PUBLIC ${Boost_LIBRARIES})
endif()

add_subdirectory(examples)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
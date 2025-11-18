# Fetch Catch2 testing framework
FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG v3.7.1
)
FetchContent_MakeAvailable(Catch2)

# Test executable
add_executable(alenats_tests
    test_main.cpp
    connection_manager_test.cpp
    connection_pool_test.cpp
    cluster_test.cpp
    subscription_test.cpp
)

target_link_libraries(alenats_tests
    PRIVATE
        alenats
        Catch2::Catch2
)

# Register tests with CTest
include(CTest)
include(Catch)
catch_discover_tests(alenats_tests)

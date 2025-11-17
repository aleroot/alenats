// Catch2 main entry point
// This file provides the main() function for all tests
#include <catch2/catch_session.hpp>

int main(int argc, char* argv[]) {
    return Catch::Session().run(argc, argv);
}

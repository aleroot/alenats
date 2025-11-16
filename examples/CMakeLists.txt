cmake_minimum_required(VERSION 3.22)
project(alenats-examples CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

message(STATUS "Building alenats examples")

add_executable(subscribe subscribe.cpp)
target_link_libraries(subscribe
  PRIVATE
  alenats
)

add_executable(publish publish.cpp)
target_link_libraries(publish
  PRIVATE
  alenats
)
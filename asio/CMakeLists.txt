project(asio CXX)

add_library(asio INTERFACE)

target_include_directories(asio INTERFACE ${PROJECT_SOURCE_DIR})
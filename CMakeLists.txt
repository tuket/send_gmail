cmake_minimum_required(VERSION 3.1)
project(send_gmail)

set (CMAKE_CXX_STANDARD 11)

add_executable(send_gmail
	main.cpp
    base64.hpp base64.cpp
    email.hpp email.cpp
)

if(UNIX)
	set(LINK_LIBS ${LINK_LIBS} "m" "dl" "pthread")
endif()

find_package(OpenSSL)
add_subdirectory(asio)

target_link_libraries(send_gmail
    "asio"
    ${LINK_LIBS} ${OPENSSL_LIBRARIES}
)
cmake_minimum_required(VERSION 3.16)
project(mock-server CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# openvpn3-core is header-only — include path only.
if(NOT DEFINED OPENVPN3_INCLUDE_DIR)
  set(OPENVPN3_INCLUDE_DIR "/openvpn3")
endif()

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(mock-server server.cpp)

target_include_directories(mock-server PRIVATE
  ${OPENVPN3_INCLUDE_DIR}
)

target_link_libraries(mock-server PRIVATE
  OpenSSL::SSL
  OpenSSL::Crypto
  Threads::Threads
)

cmake_minimum_required(VERSION 3.16.3)
project(librespot_cpp)
set(CMAKE_CXX_STANDARD 14)

find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL REQUIRED openssl)
include_directories(${OPENSSL_INCLUDE_DIRS})
message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")

add_subdirectory(lib/spdlog)

add_subdirectory(proto)
add_executable(librespot_cpp
        src/main.cpp
        src/core/session.cpp src/core/session.h
        src/core/ap_resolver.cpp src/core/ap_resolver.h
        src/network/http.cpp src/network/http.h
        lib/shannon/ShannonRef.c lib/shannon/Shannon.h
        src/crypto/diffie_hellman.cpp src/crypto/diffie_hellman.h
        src/crypto/base62.cpp src/crypto/base62.h
        src/version.cpp src/version.h
        src/crypto/cipher_pair.cpp  src/crypto/cipher_pair.h
        src/crypto/packet.cpp src/crypto/packet.h
        src/utils.cpp src/utils.h
        src/mercury/mercury_client.cpp src/mercury/mercury_client.h
        src/audio/audio_key_manager.cpp src/audio/audio_key_manager.h
        src/audio/storage/channel_manager.cpp src/audio/storage/channel_manager.h
        src/core/time_provider.cpp src/core/time_provider.h
        src/core/event_service.cpp src/core/event_service.h
        src/crypto/pbkdf2.cpp src/crypto/pbkdf2.h
        src/dealer/dealer_client.cpp src/dealer/dealer_client.h
        src/mercury/raw_mercury_request.cpp src/mercury/raw_mercury_request.h
        src/librespot_cpp.cpp src/librespot_cpp.h
        src/connection_holder.cpp src/connection_holder.h src/proxy_settings.cpp src/proxy_settings.h)

include_directories(${CMAKE_CURRENT_BINARY_DIR} ${OPENSSL_INCLUDE_DIRS})
target_include_directories(librespot_cpp PUBLIC lib/)
target_link_libraries(librespot_cpp proto ${OPENSSL_LIBRARIES} pthread spdlog::spdlog)

#target_compile_options(librespot_cpp PRIVATE -Wall -Wextra -O0 -g)
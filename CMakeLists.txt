cmake_minimum_required(VERSION 3.16.3)
project(librespot_cpp)
set(CMAKE_CXX_STANDARD 14)

find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL REQUIRED openssl)
include_directories(${OPENSSL_INCLUDE_DIRS})
message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")

add_subdirectory(proto)
add_executable(librespot_cpp
        src/main.cpp
        src/session.cpp src/session.h
        src/ap_resolver.cpp src/ap_resolver.h
        src/network/http.cpp src/network/http.h
        lib/cjson/cJSON.c lib/cjson/cJSON.h
        lib/shannon/ShannonRef.c lib/shannon/Shannon.h
        src/data/asprintf.c src/data/asprintf.h
        src/diffie_hellman.cpp src/diffie_hellman.h
        src/data/base62.cpp src/data/base62.h
        src/version.cpp src/version.h
        src/crypto/cipher_pair.cpp  src/crypto/cipher_pair.h
        src/crypto/packet.cpp src/crypto/packet.h
        src/utils.cpp src/utils.h
        src/mercury/mercury_client.cpp src/mercury/mercury_client.h
        src/audio/audio_key_manager.cpp src/audio/audio_key_manager.h
        src/audio/storage/channel_manager.cpp src/audio/storage/channel_manager.h)

include_directories(${CMAKE_CURRENT_BINARY_DIR} ${OPENSSL_INCLUDE_DIRS})
target_include_directories(librespot_cpp PUBLIC lib/)
target_link_libraries(librespot_cpp proto ${OPENSSL_LIBRARIES} pthread)
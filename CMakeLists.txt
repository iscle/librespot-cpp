cmake_minimum_required(VERSION 3.16.3)
project(librespot_cpp)
set(CMAKE_CXX_STANDARD 14)

add_executable(librespot_cpp
        # Shannon
        lib/shannon/ShannonRef.c lib/shannon/Shannon.h

        # Tremor (TODO: Add compiler flags!)
        lib/tremor/bitwise.c lib/tremor/codebook.c lib/tremor/dsp.c lib/tremor/floor0.c lib/tremor/floor1.c
        lib/tremor/floor_lookup.c lib/tremor/framing.c lib/tremor/info.c lib/tremor/mapping0.c
        lib/tremor/mdct.c lib/tremor/misc.c lib/tremor/res012.c lib/tremor/vorbisfile.c

        # librespot-c++
        src/main.cpp
        src/core/session.cpp src/core/session.h
        src/core/ap_resolver.cpp src/core/ap_resolver.h
        src/network/http.cpp src/network/http.h
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
        src/connection_holder.cpp src/connection_holder.h
        src/proxy_settings.cpp src/proxy_settings.h
        src/exceptions/mercury_exception.h
        src/exceptions/aes_key_exception.h
        src/exceptions/cdn_exception.h
        src/exceptions/content_restricted_exception.h
        src/exceptions/feeder_exception.h
        src/exceptions/chunk_exception.h
        src/exceptions/security_exception.h
        src/network/zeroconf.cpp src/network/zeroconf.h
        src/crypto/base_64.cpp src/crypto/base_64.h
        src/crypto/sha_1.cpp src/crypto/sha_1.h
        src/crypto/aes_128.cpp src/crypto/aes_128.h
        src/crypto/hmac_sha_1.cpp src/crypto/hmac_sha_1.h)

# OpenSSL
find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL REQUIRED openssl)
#target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${OPENSSL_INCLUDE_DIRS})

# spdlog
add_subdirectory(lib/spdlog)

# Protocol Buffers
include_directories(librespot_cpp ${CMAKE_CURRENT_BINARY_DIR} ${OPENSSL_INCLUDE_DIRS} lib lib/tremor lib/rapidjson/include)
add_subdirectory(proto)

# Tremor
#target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE lib/tremor)

# RapidJson
#target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE lib/rapidjson/include)

# cpp-httplib
#target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE lib/)

target_link_libraries(${CMAKE_PROJECT_NAME} ${OPENSSL_LIBRARIES} spdlog::spdlog proto pthread avahi-client avahi-common)

add_definitions(-DSPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_DEBUG)

#target_compile_options(librespot_cpp PRIVATE -Wall -Wextra -O0 -g)
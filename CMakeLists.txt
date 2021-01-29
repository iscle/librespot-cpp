cmake_minimum_required(VERSION 3.16.3)
project(librespot_c CXX)

set(CMAKE_CXX_STANDARD 11)

add_executable(librespot_c src/main.cpp
        src/session.c src/session.h
        src/ap_resolver.cpp src/ap_resolver.h
        src/network/http.cpp src/network/http.h
        lib/cjson/cJSON.c lib/cjson/cJSON.h
        src/json.c src/json.h
        src/data/asprintf.c src/data/asprintf.h
        src/diffie_hellman.c src/diffie_hellman.h
        lib/dhexchange/dhexchange.c lib/dhexchange/dhexchange.h src/data/base62.cpp src/data/base62.h)

target_include_directories(librespot_c PUBLIC lib/)

target_link_libraries(librespot_c curl)
cmake_minimum_required(VERSION 3.16.3)
project(librespot_c C)

set(CMAKE_C_STANDARD 99)

add_executable(librespot_c src/main.c
        src/session.c src/session.h
        src/ap_resolver.c src/ap_resolver.h
        src/data/list.c src/data/list.h
        src/network/http.c src/network/http.h
        lib/cjson/cJSON.c lib/cjson/cJSON.h
        src/json.c src/json.h
        src/data/asprintf.c src/data/asprintf.h
        src/diffie_hellman.c src/diffie_hellman.h
        lib/dhexchange/dhexchange.c lib/dhexchange/dhexchange.h src/data/base62.c src/data/base62.h src/data/byte_list.c src/data/byte_list.h)

target_include_directories(librespot_c PUBLIC lib/)

target_link_libraries(librespot_c curl)
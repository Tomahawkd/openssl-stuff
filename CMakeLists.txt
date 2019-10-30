cmake_minimum_required(VERSION 3.12)
project(crypto CXX C)
message(STATUS "project ${PROJECT_NAME}")

# Search OpenSSL
set(OPENSSL_ROOT_DIR /usr/local/Cellar/openssl@1.1/1.1.1d)
include_directories(/usr/local/Cellar/openssl@1.1/1.1.1d/include)
link_directories(/usr/local/Cellar/openssl@1.1/1.1.1d/lib)
find_package(openssl REQUIRED)
#pkg_search_module(OPENSSL REQUIRED openssl)

if( OPENSSL_FOUND )

    include_directories(${OPENSSL_INCLUDE_DIRS})
    link_directories(${OPENSSL_LIBRARIES})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")

else()
    # Error; with REQUIRED, pkg_search_module() will throw an error by it's own
endif()

#include_directories(/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)

add_executable(des_ecb des_ecb.c des_ecb.h common_ecb.h main.c)
target_compile_definitions(des_ecb PRIVATE -DDES_ECB)
#add_definitions(-DDES_ECB)
target_link_libraries(des_ecb ${OPENSSL_LIBRARIES})

add_executable(aes_ecb aes_ecb.c common_ecb.h main.c aes_ecb.h)
#add_definitions(-DAES)
target_compile_definitions(aes_ecb PRIVATE -DAES_ECB)
target_link_libraries(aes_ecb ${OPENSSL_LIBRARIES})

add_executable(rc4 rc4.c common_ecb.h main.c rc4.h)
#add_definitions(-DRC4_T)
target_compile_definitions(rc4 PRIVATE -DRC4_T)
target_link_libraries(rc4 ${OPENSSL_LIBRARIES})

add_executable(x509 x509.c)
target_link_libraries(x509 ${OPENSSL_LIBRARIES})

add_executable(server server.c)
target_link_libraries(server ${OPENSSL_LIBRARIES})

add_executable(client client.c)
target_link_libraries(client ${OPENSSL_LIBRARIES})

add_executable(drbg drbg_test.c)
target_link_libraries(drbg ${OPENSSL_LIBRARIES})

add_executable(digest digest.c)
target_link_libraries(digest ${OPENSSL_LIBRARIES})

add_executable(ciph ciph.c)
target_link_libraries(ciph ${OPENSSL_LIBRARIES})
cmake_minimum_required(VERSION 3.30)
project(blocks)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")

find_package(PkgConfig REQUIRED)
pkg_check_modules(BOTAN REQUIRED botan-3)
pkg_check_modules(OQS REQUIRED liboqs)
pkg_check_modules(OPENSSL REQUIRED openssl)

add_executable(blocks
        main.cpp
        hash_utils.h
        hash_utils.cpp
        varint.h
        varint.cpp
        transaction_serializer.h
        benchmark_runner.h
        transaction_serializer.cpp
        benchmark_runner.cpp
)

target_include_directories(blocks PUBLIC ${BOTAN_INCLUDE_DIRS})
target_link_directories(blocks PUBLIC ${BOTAN_LIBRARY_DIRS})
target_compile_definitions(blocks PUBLIC ${BOTAN_CFLAGS_OTHER})
target_include_directories(blocks PUBLIC ${OQS_INCLUDE_DIRS})
target_link_directories(blocks PUBLIC ${OQS_LIBRARY_DIRS})
target_compile_definitions(blocks PUBLIC ${OQS_CFLAGS_OTHER})
target_link_libraries(blocks PUBLIC ${BOTAN_LIBRARIES})
target_link_libraries(blocks PUBLIC ${OQS_LIBRARIES})

target_include_directories(blocks PUBLIC ${OPENSSL_INCLUDE_DIRS})
target_link_directories(blocks PUBLIC ${OPENSSL_LIBRARY_DIRS})
target_link_libraries(blocks PUBLIC ${OPENSSL_LIBRARIES})
target_compile_options(blocks PUBLIC ${OPENSSL_CFLAGS_OTHER})



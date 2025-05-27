cmake_minimum_required(VERSION 3.30)
project(benchmarking)

set(CMAKE_CXX_STANDARD 20)

find_package(PkgConfig REQUIRED)
pkg_check_modules(BOTAN REQUIRED botan-3)
pkg_check_modules(OQS REQUIRED liboqs)
pkg_check_modules(OPENSSL REQUIRED openssl)

add_executable(benchmarking
        ml_dsa.cpp
        main.cpp
        util.h
        util.cpp
        sphincs_benchmark.cpp
        falcon.cpp
        sphincs_fast.cpp
        ecdsa.cpp
        ecdsa_falcon.cpp
        ecdsa_mldsa.cpp
        ecdsa_sphincs_robust.cpp
        ecdsa_sphincs_simple.cpp
)
target_include_directories(benchmarking PUBLIC ${BOTAN_INCLUDE_DIRS})
target_link_directories(benchmarking PUBLIC ${BOTAN_LIBRARY_DIRS})
target_compile_definitions(benchmarking PUBLIC ${BOTAN_CFLAGS_OTHER})
target_include_directories(benchmarking PUBLIC ${OQS_INCLUDE_DIRS})
target_link_directories(benchmarking PUBLIC ${OQS_LIBRARY_DIRS})
target_compile_definitions(benchmarking PUBLIC ${OQS_CFLAGS_OTHER})
target_link_libraries(benchmarking PUBLIC ${BOTAN_LIBRARIES})
target_link_libraries(benchmarking PUBLIC ${OQS_LIBRARIES})

target_include_directories(benchmarking PUBLIC ${OPENSSL_INCLUDE_DIRS})
target_link_directories(benchmarking PUBLIC ${OPENSSL_LIBRARY_DIRS})
target_link_libraries(benchmarking PUBLIC ${OPENSSL_LIBRARIES})
target_compile_options(benchmarking PUBLIC ${OPENSSL_CFLAGS_OTHER})


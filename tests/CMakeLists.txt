# Copyright (C) 2022 Intel Corporation

# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.15)

project(ippcp_encryptor_test VERSION 0.0.1)

option(COVERAGE "Enable test coverage report" ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(ippcp_encryptor_test_CMAKE_EXE_LINKER_FLAGS "-u ippcp_reg")
add_executable(ippcp_encryptor_test ../ippcp_provider.cc ippcp_encryptor_test.cc)


if(NOT DEFINED IPPCRYPTOROOT)
  find_package(ippcp REQUIRED)
  if(ippcp_FOUND)
    message(STATUS "Found ippcp: ${ippcp_DIR}")
    target_link_libraries(ippcp_encryptor_test ippcp::ippcp)
  endif()
else()
  message(STATUS "Using IPPCRYPTOROOT: ${IPPCRYPTOROOT}")
  include_directories(${IPPCRYPTOROOT}/include)
  target_link_libraries(ippcp_encryptor_test ippcp)
endif()

if(NOT DEFINED ROCKSDB_PATH)
  find_package(RocksDB REQUIRED)
  if(RocksDB_FOUND)
    message(STATUS "Found RocksDB: ${RocksDB_DIR}")
    target_link_libraries(ippcp_encryptor_test rocksdb)
  endif()
elseif(DEFINED ROCKSDB_PATH)
  message(STATUS "Using ROCKSDB_PATH: ${ROCKSDB_PATH}")
  include_directories(${ROCKSDB_PATH} ${ROCKSDB_PATH}/include)
  target_link_directories(ippcp_encryptor_test PUBLIC ${ROCKSDB_PATH})
  target_link_libraries(ippcp_encryptor_test rocksdb)
endif()

find_package(GTest REQUIRED)
target_link_libraries(ippcp_encryptor_test gtest)

add_compile_definitions(ROCKSDB_PLATFORM_POSIX)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-rtti")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
if(COVERAGE)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage")
endif()

add_custom_target(run
    COMMAND ./ippcp_encryptor_test
    DEPENDS ippcp_encryptor_test
)

add_custom_target(coverage
    COMMAND lcov --directory . --capture --output-file ippcp_encryptor_test.info && genhtml -o html ippcp_encryptor_test.info
)
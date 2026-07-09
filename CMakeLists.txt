cmake_minimum_required(VERSION 3.20)

project(quic_affinity
  VERSION 0.1.0
  DESCRIPTION "Linux QUIC worker affinity layer"
  LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(QAFF_BUILD_BPF "Build eBPF dataplane object" ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

add_library(qaffinity
  src/bpf_loader.c
  src/qaffinity.c
  src/quic_parser.c)

target_include_directories(qaffinity
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE
    ${LIBBPF_INCLUDE_DIRS})

target_link_libraries(qaffinity
  PUBLIC
    ${LIBBPF_LIBRARIES})

target_compile_options(qaffinity PRIVATE -Wall -Wextra -Wpedantic)

add_executable(qaffctl
  tools/qaffctl/main.c)

target_link_libraries(qaffctl PRIVATE qaffinity)
target_compile_options(qaffctl PRIVATE -Wall -Wextra -Wpedantic)

enable_testing()

add_executable(test_quic_parser
  tests/test_quic_parser.c)

target_link_libraries(test_quic_parser PRIVATE qaffinity)
target_compile_options(test_quic_parser PRIVATE -Wall -Wextra -Wpedantic)

add_test(NAME quic_parser COMMAND test_quic_parser)

add_executable(test_reuseport_smoke
  tests/test_reuseport_smoke.c)

target_link_libraries(test_reuseport_smoke PRIVATE qaffinity)
target_compile_options(test_reuseport_smoke PRIVATE -Wall -Wextra -Wpedantic)

add_test(NAME reuseport_smoke
  COMMAND /bin/sh
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_reuseport_smoke.sh
    $<TARGET_FILE:test_reuseport_smoke>
    ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o)
set_tests_properties(reuseport_smoke PROPERTIES SKIP_RETURN_CODE 77)

if(QAFF_BUILD_BPF)
  find_program(CLANG_EXECUTABLE clang)
  if(CLANG_EXECUTABLE)
    add_custom_command(
      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o
      COMMAND ${CLANG_EXECUTABLE}
        -O2
        -g
        -target bpf
        -D__TARGET_ARCH_x86
        -DQAFF_BPF
        -I${CMAKE_CURRENT_SOURCE_DIR}/bpf
        -I${CMAKE_CURRENT_SOURCE_DIR}/include
        -I/usr/include/x86_64-linux-gnu
        -c ${CMAKE_CURRENT_SOURCE_DIR}/bpf/qaff_reuseport.bpf.c
        -o ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o
      DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/bpf/qaff_reuseport.bpf.c
        ${CMAKE_CURRENT_SOURCE_DIR}/bpf/qaff_bpf.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/quic_affinity/wire.h
      VERBATIM)

    add_custom_target(qaff_bpf ALL
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o)
    add_dependencies(test_reuseport_smoke qaff_bpf)
  else()
    message(WARNING "clang not found; eBPF object will not be built")
  endif()
endif()

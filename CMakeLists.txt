cmake_minimum_required(VERSION 3.20)

project(quic_affinity
  VERSION 0.1.0
  DESCRIPTION "Linux QUIC worker affinity layer"
  LANGUAGES C)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(QAFF_BUILD_BPF "Build eBPF dataplane object" ON)
option(QAFF_BUILD_QUICHE_EXAMPLES "Build optional quiche integration examples" ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

add_library(qaffinity
  src/cid_profile.c
  src/control_client.c
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

add_executable(qaffd
  qaffd/main.c)

target_link_libraries(qaffd PRIVATE qaffinity)
target_compile_options(qaffd PRIVATE -Wall -Wextra -Wpedantic)

install(TARGETS qaffinity
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(TARGETS qaffctl
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(TARGETS qaffd
  RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})

install(DIRECTORY include/quic_affinity
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(FILES packaging/systemd/qaffd@.service
  DESTINATION lib/systemd/system)

install(FILES packaging/systemd/quic-affinity.tmpfiles
  RENAME quic-affinity.conf
  DESTINATION lib/tmpfiles.d)

install(FILES packaging/systemd/quic-affinity.sysusers
  RENAME quic-affinity.conf
  DESTINATION lib/sysusers.d)

install(FILES packaging/systemd/qaffd.env.example
  DESTINATION ${CMAKE_INSTALL_DOCDIR}/examples)

install(FILES README.md
  DESTINATION ${CMAKE_INSTALL_DOCDIR})

install(FILES LICENSE
  DESTINATION ${CMAKE_INSTALL_DOCDIR})

add_executable(qaff_minimal_registry
  examples/minimal_registry/main.c)

target_link_libraries(qaff_minimal_registry PRIVATE qaffinity)
target_compile_options(qaff_minimal_registry PRIVATE -Wall -Wextra -Wpedantic)

add_executable(qaff_minimal_control
  examples/minimal_control/main.c)

target_link_libraries(qaff_minimal_control PRIVATE qaffinity)
target_compile_options(qaff_minimal_control PRIVATE -Wall -Wextra -Wpedantic)

set(QAFF_QUICHE_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/quiche/quiche/include)
set(QAFF_QUICHE_LIBRARY ${CMAKE_CURRENT_SOURCE_DIR}/third_party/quiche/target/debug/libquiche.so)

if(QAFF_BUILD_QUICHE_EXAMPLES AND
   EXISTS ${QAFF_QUICHE_INCLUDE_DIR}/quiche.h AND
   EXISTS ${QAFF_QUICHE_LIBRARY})
  add_executable(qaff_quiche_control_probe
    examples/quiche_control_probe/main.c)

  target_include_directories(qaff_quiche_control_probe PRIVATE
    ${QAFF_QUICHE_INCLUDE_DIR})
  target_link_libraries(qaff_quiche_control_probe PRIVATE
    qaffinity
    ${QAFF_QUICHE_LIBRARY})
  set_target_properties(qaff_quiche_control_probe PROPERTIES
    BUILD_RPATH "$ORIGIN;${CMAKE_CURRENT_SOURCE_DIR}/third_party/quiche/target/debug")
  add_custom_command(TARGET qaff_quiche_control_probe POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E create_symlink
      ${QAFF_QUICHE_LIBRARY}
      $<TARGET_FILE_DIR:qaff_quiche_control_probe>/libquiche.so.0
    VERBATIM)
  target_compile_options(qaff_quiche_control_probe PRIVATE
    -Wall -Wextra -Wpedantic)

  add_executable(qaff_quiche_udp_smoke
    examples/quiche_udp_smoke/main.c)

  target_include_directories(qaff_quiche_udp_smoke PRIVATE
    ${QAFF_QUICHE_INCLUDE_DIR})
  target_link_libraries(qaff_quiche_udp_smoke PRIVATE
    qaffinity
    ${QAFF_QUICHE_LIBRARY})
  set_target_properties(qaff_quiche_udp_smoke PROPERTIES
    BUILD_RPATH "$ORIGIN;${CMAKE_CURRENT_SOURCE_DIR}/third_party/quiche/target/debug")
  add_custom_command(TARGET qaff_quiche_udp_smoke POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E create_symlink
      ${QAFF_QUICHE_LIBRARY}
      $<TARGET_FILE_DIR:qaff_quiche_udp_smoke>/libquiche.so.0
    VERBATIM)
  target_compile_options(qaff_quiche_udp_smoke PRIVATE
    -Wall -Wextra -Wpedantic)
else()
  message(STATUS "quiche integration example disabled; build quiche FFI under third_party/quiche to enable it")
endif()

enable_testing()

add_executable(test_quic_parser
  tests/test_quic_parser.c)

target_link_libraries(test_quic_parser PRIVATE qaffinity)
target_compile_options(test_quic_parser PRIVATE -Wall -Wextra -Wpedantic)

add_test(NAME quic_parser COMMAND test_quic_parser)

add_executable(test_cid_profile
  tests/test_cid_profile.c)

target_link_libraries(test_cid_profile PRIVATE qaffinity)
target_compile_options(test_cid_profile PRIVATE -Wall -Wextra -Wpedantic)

add_test(NAME cid_profile COMMAND $<TARGET_FILE:test_cid_profile>)

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

add_executable(test_qaffd_control
  tests/test_qaffd_control.c)

target_link_libraries(test_qaffd_control PRIVATE qaffinity)
target_compile_options(test_qaffd_control PRIVATE -Wall -Wextra -Wpedantic)

add_test(NAME qaffd_control
  COMMAND /bin/sh
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_qaffd_control.sh
    $<TARGET_FILE:qaffd>
    $<TARGET_FILE:test_qaffd_control>
    ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o)
set_tests_properties(qaffd_control PROPERTIES SKIP_RETURN_CODE 77)

add_executable(test_qaffd_restart
  tests/test_qaffd_restart.c)

target_link_libraries(test_qaffd_restart PRIVATE qaffinity)
target_compile_options(test_qaffd_restart PRIVATE -Wall -Wextra -Wpedantic)

add_test(NAME qaffd_restart
  COMMAND /bin/sh
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_qaffd_restart.sh
    $<TARGET_FILE:qaffd>
    $<TARGET_FILE:test_qaffd_restart>
    ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o)
set_tests_properties(qaffd_restart PROPERTIES SKIP_RETURN_CODE 77)

add_executable(test_qaffd_egress
  tests/test_qaffd_egress.c)

target_link_libraries(test_qaffd_egress PRIVATE qaffinity)
target_compile_options(test_qaffd_egress PRIVATE -Wall -Wextra -Wpedantic)

add_test(NAME qaffctl_control
  COMMAND /bin/sh
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_qaffctl_control.sh
    $<TARGET_FILE:qaffd>
    $<TARGET_FILE:qaffctl>
    ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o)
set_tests_properties(qaffctl_control PROPERTIES SKIP_RETURN_CODE 77)

add_test(NAME minimal_control_example
  COMMAND /bin/sh
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_minimal_control_example.sh
    $<TARGET_FILE:qaffd>
    $<TARGET_FILE:qaffctl>
    $<TARGET_FILE:qaff_minimal_control>
    ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o)
set_tests_properties(minimal_control_example PROPERTIES SKIP_RETURN_CODE 77)

add_test(NAME egress_attach_smoke
  COMMAND /bin/sh
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_egress_attach_smoke.sh
    $<TARGET_FILE:qaffd>
    $<TARGET_FILE:qaffctl>
    ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o)
set_tests_properties(egress_attach_smoke PROPERTIES SKIP_RETURN_CODE 77)

add_test(NAME egress_learn_smoke
  COMMAND /bin/sh
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_egress_learn_smoke.sh
    $<TARGET_FILE:qaffd>
    $<TARGET_FILE:qaffctl>
    $<TARGET_FILE:test_qaffd_egress>
    ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o)
set_tests_properties(egress_learn_smoke PROPERTIES SKIP_RETURN_CODE 77)

if(TARGET qaff_quiche_control_probe)
  add_test(NAME quiche_control_probe
    COMMAND /bin/sh
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_quiche_control_probe.sh
      $<TARGET_FILE:qaffd>
      $<TARGET_FILE:qaffctl>
      $<TARGET_FILE:qaff_quiche_control_probe>
      ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o)
  set_tests_properties(quiche_control_probe PROPERTIES SKIP_RETURN_CODE 77)
endif()

if(TARGET qaff_quiche_udp_smoke)
  add_test(NAME quiche_udp_smoke
    COMMAND /bin/sh
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_quiche_udp_smoke.sh
      $<TARGET_FILE:qaffd>
      $<TARGET_FILE:qaff_quiche_udp_smoke>
      ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o
      ${CMAKE_CURRENT_SOURCE_DIR}/third_party/quiche/quiche/examples/cert.crt
      ${CMAKE_CURRENT_SOURCE_DIR}/third_party/quiche/quiche/examples/cert.key)
  set_tests_properties(quiche_udp_smoke PROPERTIES SKIP_RETURN_CODE 77)
endif()

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
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o
      DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/quic-affinity)
    add_dependencies(test_reuseport_smoke qaff_bpf)
    add_dependencies(qaffd qaff_bpf)
    add_dependencies(test_qaffd_control qaff_bpf)
    add_dependencies(test_qaffd_restart qaff_bpf)
    add_dependencies(test_qaffd_egress qaff_bpf)
  else()
    message(WARNING "clang not found; eBPF object will not be built")
  endif()
endif()

if(TARGET qaff_bpf)
  add_test(NAME packaging_smoke
    COMMAND /bin/sh
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_packaging_smoke.sh
      ${CMAKE_CURRENT_BINARY_DIR})
endif()

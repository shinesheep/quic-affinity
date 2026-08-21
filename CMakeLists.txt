cmake_minimum_required(VERSION 3.20)

project(quic_affinity
  VERSION 0.1.0
  DESCRIPTION "Linux QUIC worker affinity layer"
  LANGUAGES C)

include(GNUInstallDirs)
include(CTest)
include(CMakePackageConfigHelpers)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(QAFF_BUILD_BPF "Build eBPF dataplane object" ON)
option(QAFF_BUILD_DAEMON "Build and install qaffd" ON)
option(QAFF_BUILD_TOOLS "Build and install qaffctl and qaff-agent" ON)
option(QAFF_BUILD_EXAMPLES "Build example programs" ON)
option(QAFF_BUILD_QUICHE_EXAMPLES "Build optional quiche integration examples" ON)
set(QAFF_BPF_TARGET_ARCH "" CACHE STRING
  "libbpf target architecture name (x86, arm64, arm, powerpc, s390, mips, riscv, or loongarch)")
set(QAFF_BPF_CLANG_TARGET "" CACHE STRING
  "clang BPF target triple (bpfel or bpfeb); derived from the target byte order by default")
set(QAFF_BPF_SYSTEM_INCLUDE_DIR "" CACHE PATH
  "Directory containing architecture-specific asm headers for the BPF build")

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)

add_library(qaffinity
  src/cid_profile.c
  src/control_client.c
  src/bpf_loader.c
  src/qaffinity.c
  src/quic_parser.c)

target_include_directories(qaffinity
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/internal)

target_link_libraries(qaffinity
  PUBLIC
    PkgConfig::LIBBPF)

target_compile_options(qaffinity PRIVATE -Wall -Wextra -Wpedantic)
add_library(quic-affinity::qaffinity ALIAS qaffinity)

if(QAFF_BUILD_TOOLS)
  add_executable(qaffctl
    tools/qaffctl/main.c)

  target_link_libraries(qaffctl PRIVATE qaffinity)
  target_compile_definitions(qaffctl PRIVATE
    QAFF_PROJECT_VERSION="${PROJECT_VERSION}")
  target_compile_options(qaffctl PRIVATE -Wall -Wextra -Wpedantic)

  add_executable(qaff-agent
    tools/qaff-agent/main.c)

  target_link_libraries(qaff-agent PRIVATE qaffinity)
  target_compile_options(qaff-agent PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(QAFF_BUILD_DAEMON)
  add_executable(qaffd
    qaffd/main.c)

  target_link_libraries(qaffd PRIVATE qaffinity)
  target_include_directories(qaffd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/internal)
  target_compile_options(qaffd PRIVATE -Wall -Wextra -Wpedantic)
endif()

install(TARGETS qaffinity EXPORT quic-affinityTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(TARGET qaffctl)
  install(TARGETS qaffctl
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(TARGET qaffd)
  install(TARGETS qaffd
    RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
endif()

if(TARGET qaff-agent)
  install(TARGETS qaff-agent
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

install(DIRECTORY include/quic_affinity
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(TARGET qaffd)
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
endif()

if(TARGET qaff-agent)
  install(FILES packaging/systemd/qaff-agent@.service
    DESTINATION lib/systemd/system)
  install(FILES packaging/systemd/qaff-agent.env.example
    DESTINATION ${CMAKE_INSTALL_DOCDIR}/examples)
endif()

install(FILES README.md
  DESTINATION ${CMAKE_INSTALL_DOCDIR})

install(FILES LICENSE
  DESTINATION ${CMAKE_INSTALL_DOCDIR})

configure_package_config_file(
  cmake/quic-affinityConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/quic-affinityConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/quic-affinity)
write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/quic-affinityConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)
install(EXPORT quic-affinityTargets
  FILE quic-affinityTargets.cmake
  NAMESPACE quic-affinity::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/quic-affinity)
install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/quic-affinityConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/quic-affinityConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/quic-affinity)

set(QAFF_PKGCONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
file(RELATIVE_PATH QAFF_PC_PREFIX_FROM_PKGCONFIG
  "/${QAFF_PKGCONFIG_INSTALL_DIR}" "/")
configure_file(packaging/quic-affinity.pc.in
  ${CMAKE_CURRENT_BINARY_DIR}/quic-affinity.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/quic-affinity.pc
  DESTINATION ${QAFF_PKGCONFIG_INSTALL_DIR})

if(QAFF_BUILD_EXAMPLES)
  add_executable(qaff_minimal_registry
    examples/minimal_registry/main.c)

  target_link_libraries(qaff_minimal_registry PRIVATE qaffinity)
  target_compile_options(qaff_minimal_registry PRIVATE -Wall -Wextra -Wpedantic)

  add_executable(qaff_minimal_control
    examples/minimal_control/main.c)

  target_link_libraries(qaff_minimal_control PRIVATE qaffinity)
  target_compile_options(qaff_minimal_control PRIVATE -Wall -Wextra -Wpedantic)
endif()

set(QAFF_QUICHE_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/quiche/quiche/include)
set(QAFF_QUICHE_LIBRARY ${CMAKE_CURRENT_SOURCE_DIR}/third_party/quiche/target/debug/libquiche.so)

if(QAFF_BUILD_EXAMPLES AND QAFF_BUILD_QUICHE_EXAMPLES AND
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
elseif(QAFF_BUILD_EXAMPLES AND QAFF_BUILD_QUICHE_EXAMPLES)
  message(STATUS "quiche integration example disabled; build quiche FFI under third_party/quiche to enable it")
endif()

if(BUILD_TESTING)
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

  if(QAFF_BUILD_BPF)
    add_executable(test_reuseport_smoke
      tests/test_reuseport_smoke.c)
    target_link_libraries(test_reuseport_smoke PRIVATE qaffinity)
    target_compile_options(test_reuseport_smoke PRIVATE
      -Wall -Wextra -Wpedantic)
    add_test(NAME reuseport_smoke
      COMMAND /bin/sh
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_reuseport_smoke.sh
        $<TARGET_FILE:test_reuseport_smoke>
        ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o)
    set_tests_properties(reuseport_smoke PROPERTIES SKIP_RETURN_CODE 77)

    if(TARGET qaffd)
      add_executable(test_qaffd_control
        tests/test_qaffd_control.c)
      target_link_libraries(test_qaffd_control PRIVATE qaffinity)
      target_compile_options(test_qaffd_control PRIVATE
        -Wall -Wextra -Wpedantic)
      add_test(NAME qaffd_control
        COMMAND /bin/sh
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_qaffd_control.sh
          $<TARGET_FILE:qaffd>
          $<TARGET_FILE:test_qaffd_control>
          ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o)
      set_tests_properties(qaffd_control PROPERTIES
        SKIP_RETURN_CODE 77
        TIMEOUT 20)

      add_executable(test_qaffd_restart
        tests/test_qaffd_restart.c)
      target_link_libraries(test_qaffd_restart PRIVATE qaffinity)
      target_compile_options(test_qaffd_restart PRIVATE
        -Wall -Wextra -Wpedantic)
      add_test(NAME qaffd_restart
        COMMAND /bin/sh
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_qaffd_restart.sh
          $<TARGET_FILE:qaffd>
          $<TARGET_FILE:test_qaffd_restart>
          ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o)
      set_tests_properties(qaffd_restart PROPERTIES
        SKIP_RETURN_CODE 77
        TIMEOUT 20)

      add_executable(test_qaffd_egress
        tests/test_qaffd_egress.c)
      target_link_libraries(test_qaffd_egress PRIVATE qaffinity)
      target_compile_options(test_qaffd_egress PRIVATE
        -Wall -Wextra -Wpedantic)
    endif()

    if(TARGET qaffd AND TARGET qaffctl AND TARGET qaff-agent)
      add_executable(test_qaff_agent_target
        tests/test_qaff_agent_target.c)
      target_compile_options(test_qaff_agent_target PRIVATE
        -Wall -Wextra -Wpedantic)
      add_test(NAME qaff_agent
        COMMAND /bin/sh
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_qaff_agent.sh
          $<TARGET_FILE:qaffd>
          $<TARGET_FILE:qaffctl>
          $<TARGET_FILE:qaff-agent>
          $<TARGET_FILE:test_qaff_agent_target>
          ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o)
      set_tests_properties(qaff_agent PROPERTIES
        SKIP_RETURN_CODE 77
        TIMEOUT 20)
    endif()

    if(TARGET qaffd AND TARGET qaffctl)
      add_test(NAME qaffctl_control
        COMMAND /bin/sh
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_qaffctl_control.sh
          $<TARGET_FILE:qaffd>
          $<TARGET_FILE:qaffctl>
          ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o)
      set_tests_properties(qaffctl_control PROPERTIES SKIP_RETURN_CODE 77)

      add_test(NAME egress_attach_smoke
        COMMAND /bin/sh
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_egress_attach_smoke.sh
          $<TARGET_FILE:qaffd>
          $<TARGET_FILE:qaffctl>
          ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o)
      set_tests_properties(egress_attach_smoke PROPERTIES SKIP_RETURN_CODE 77)
    endif()

    if(TARGET qaffd AND TARGET qaffctl AND TARGET qaff_minimal_control)
      add_test(NAME minimal_control_example
        COMMAND /bin/sh
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_minimal_control_example.sh
          $<TARGET_FILE:qaffd>
          $<TARGET_FILE:qaffctl>
          $<TARGET_FILE:qaff_minimal_control>
          ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o)
      set_tests_properties(minimal_control_example PROPERTIES
        SKIP_RETURN_CODE 77)
    endif()

    if(TARGET qaffd AND TARGET qaffctl AND TARGET test_qaffd_egress)
      add_test(NAME egress_learn_smoke
        COMMAND /bin/sh
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_egress_learn_smoke.sh
          $<TARGET_FILE:qaffd>
          $<TARGET_FILE:qaffctl>
          $<TARGET_FILE:test_qaffd_egress>
          ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o)
      set_tests_properties(egress_learn_smoke PROPERTIES SKIP_RETURN_CODE 77)
    endif()

    if(TARGET qaffd AND TARGET qaffctl AND TARGET qaff_quiche_control_probe)
      add_test(NAME quiche_control_probe
        COMMAND /bin/sh
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_quiche_control_probe.sh
          $<TARGET_FILE:qaffd>
          $<TARGET_FILE:qaffctl>
          $<TARGET_FILE:qaff_quiche_control_probe>
          ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o)
      set_tests_properties(quiche_control_probe PROPERTIES SKIP_RETURN_CODE 77)
    endif()

    if(TARGET qaffd AND TARGET qaffctl AND TARGET qaff_quiche_udp_smoke)
      add_test(NAME quiche_udp_smoke
        COMMAND /bin/sh
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_quiche_udp_smoke.sh
          $<TARGET_FILE:qaffd>
          $<TARGET_FILE:qaff_quiche_udp_smoke>
          ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o
          ${CMAKE_CURRENT_SOURCE_DIR}/third_party/quiche/quiche/examples/cert.crt
          ${CMAKE_CURRENT_SOURCE_DIR}/third_party/quiche/quiche/examples/cert.key)
      set_tests_properties(quiche_udp_smoke PROPERTIES SKIP_RETURN_CODE 77)

      add_test(NAME quiche_passive_egress_smoke
        COMMAND /bin/sh
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_quiche_passive_egress_smoke.sh
          $<TARGET_FILE:qaffd>
          $<TARGET_FILE:qaffctl>
          $<TARGET_FILE:qaff_quiche_udp_smoke>
          ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o
          ${CMAKE_CURRENT_SOURCE_DIR}/third_party/quiche/quiche/examples/cert.crt
          ${CMAKE_CURRENT_SOURCE_DIR}/third_party/quiche/quiche/examples/cert.key)
      set_tests_properties(quiche_passive_egress_smoke PROPERTIES
        SKIP_RETURN_CODE 77)
    endif()
  endif()
endif()

if(QAFF_BUILD_BPF)
  find_program(CLANG_EXECUTABLE clang REQUIRED)
  execute_process(
    COMMAND ${CLANG_EXECUTABLE} -print-targets
    RESULT_VARIABLE QAFF_CLANG_TARGETS_RESULT
    OUTPUT_VARIABLE QAFF_CLANG_TARGETS
    ERROR_VARIABLE QAFF_CLANG_TARGETS_ERROR)
  if(NOT QAFF_CLANG_TARGETS_RESULT EQUAL 0)
    message(FATAL_ERROR
      "Could not inspect targets provided by ${CLANG_EXECUTABLE}: ${QAFF_CLANG_TARGETS_ERROR}")
  endif()

  if(NOT QAFF_BPF_CLANG_TARGET)
    if(CMAKE_C_BYTE_ORDER STREQUAL "BIG_ENDIAN")
      set(QAFF_BPF_CLANG_TARGET bpfeb)
    elseif(CMAKE_C_BYTE_ORDER STREQUAL "LITTLE_ENDIAN")
      set(QAFF_BPF_CLANG_TARGET bpfel)
    else()
      message(FATAL_ERROR
        "Could not determine target byte order; set QAFF_BPF_CLANG_TARGET explicitly")
    endif()
  endif()
  if(NOT QAFF_BPF_CLANG_TARGET MATCHES "^(bpfel|bpfeb)$")
    message(FATAL_ERROR "QAFF_BPF_CLANG_TARGET must be bpfel or bpfeb")
  endif()
  if(NOT QAFF_CLANG_TARGETS MATCHES
     "(^|\n)[ \t]*${QAFF_BPF_CLANG_TARGET}[ \t]")
    message(FATAL_ERROR
      "${CLANG_EXECUTABLE} does not provide the ${QAFF_BPF_CLANG_TARGET} target; install a clang build with BPF support or set QAFF_BUILD_BPF=OFF")
  endif()

  if(NOT QAFF_BPF_TARGET_ARCH)
    string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" QAFF_SYSTEM_PROCESSOR_LOWER)
    if(QAFF_SYSTEM_PROCESSOR_LOWER MATCHES "^(x86_64|amd64|i[3-6]86)$")
      set(QAFF_BPF_TARGET_ARCH x86)
    elseif(QAFF_SYSTEM_PROCESSOR_LOWER MATCHES "^(aarch64|arm64)$")
      set(QAFF_BPF_TARGET_ARCH arm64)
    elseif(QAFF_SYSTEM_PROCESSOR_LOWER MATCHES "^arm")
      set(QAFF_BPF_TARGET_ARCH arm)
    elseif(QAFF_SYSTEM_PROCESSOR_LOWER MATCHES "^(ppc64|ppc64le|powerpc.*)$")
      set(QAFF_BPF_TARGET_ARCH powerpc)
    elseif(QAFF_SYSTEM_PROCESSOR_LOWER MATCHES "^s390")
      set(QAFF_BPF_TARGET_ARCH s390)
    elseif(QAFF_SYSTEM_PROCESSOR_LOWER MATCHES "^mips")
      set(QAFF_BPF_TARGET_ARCH mips)
    elseif(QAFF_SYSTEM_PROCESSOR_LOWER MATCHES "^riscv")
      set(QAFF_BPF_TARGET_ARCH riscv)
    elseif(QAFF_SYSTEM_PROCESSOR_LOWER MATCHES "^loongarch")
      set(QAFF_BPF_TARGET_ARCH loongarch)
    else()
      message(FATAL_ERROR
        "Unsupported BPF target architecture '${CMAKE_SYSTEM_PROCESSOR}'; set QAFF_BPF_TARGET_ARCH explicitly")
    endif()
  endif()
  if(NOT QAFF_BPF_TARGET_ARCH MATCHES
     "^(x86|arm64|arm|powerpc|s390|mips|riscv|loongarch)$")
    message(FATAL_ERROR "Invalid QAFF_BPF_TARGET_ARCH '${QAFF_BPF_TARGET_ARCH}'")
  endif()

  if(NOT QAFF_BPF_SYSTEM_INCLUDE_DIR)
    foreach(QAFF_INCLUDE_CANDIDATE IN LISTS CMAKE_C_IMPLICIT_INCLUDE_DIRECTORIES)
      if(EXISTS "${QAFF_INCLUDE_CANDIDATE}/asm/types.h")
        set(QAFF_BPF_SYSTEM_INCLUDE_DIR "${QAFF_INCLUDE_CANDIDATE}")
        break()
      endif()
    endforeach()
  endif()
  if(NOT QAFF_BPF_SYSTEM_INCLUDE_DIR OR
     NOT EXISTS "${QAFF_BPF_SYSTEM_INCLUDE_DIR}/asm/types.h")
    message(FATAL_ERROR
      "Could not find architecture-specific asm/types.h; set QAFF_BPF_SYSTEM_INCLUDE_DIR")
  endif()

  message(STATUS
    "BPF clang target: ${QAFF_BPF_CLANG_TARGET}; architecture: ${QAFF_BPF_TARGET_ARCH}; system headers: ${QAFF_BPF_SYSTEM_INCLUDE_DIR}")
  add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/qaff_reuseport.bpf.o
    COMMAND ${CLANG_EXECUTABLE}
      -O2
      -g
      -target ${QAFF_BPF_CLANG_TARGET}
      -D__TARGET_ARCH_${QAFF_BPF_TARGET_ARCH}
      -DQAFF_BPF
      -I${CMAKE_CURRENT_SOURCE_DIR}/bpf
      -I${CMAKE_CURRENT_SOURCE_DIR}/include
      -I${QAFF_BPF_SYSTEM_INCLUDE_DIR}
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
  foreach(QAFF_BPF_DEPENDENT_TARGET IN ITEMS
      qaffd
      test_reuseport_smoke
      test_qaffd_control
      test_qaffd_restart
      test_qaffd_egress)
    if(TARGET ${QAFF_BPF_DEPENDENT_TARGET})
      add_dependencies(${QAFF_BPF_DEPENDENT_TARGET} qaff_bpf)
    endif()
  endforeach()
endif()

if(BUILD_TESTING AND TARGET qaff_bpf AND TARGET qaffd AND
   TARGET qaffctl AND TARGET qaff-agent)
  add_test(NAME packaging_smoke
    COMMAND /bin/sh
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_packaging_smoke.sh
      ${CMAKE_CURRENT_BINARY_DIR})
endif()

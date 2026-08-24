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
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

option(QAFF_BUILD_BPF "Build eBPF dataplane object" ON)
option(QAFF_BUILD_DAEMON "Build and install qaffd" ON)
option(QAFF_BUILD_TOOLS "Build and install qaffctl and qaff-agent" ON)
option(QAFF_BUILD_EXAMPLES "Build example programs" ON)
option(QAFF_BUILD_QUICHE_EXAMPLES "Build optional quiche integration examples" ON)
option(QAFF_BUILD_FUZZERS "Build Clang libFuzzer targets" OFF)
set(QAFF_BPF_TARGET_ARCH "" CACHE STRING
  "libbpf target architecture name (x86, arm64, arm, powerpc, s390, mips, riscv, or loongarch)")
set(QAFF_BPF_CLANG_TARGET "" CACHE STRING
  "clang BPF target triple (bpfel or bpfeb); derived from the target byte order by default")
set(QAFF_BPF_SYSTEM_INCLUDE_DIR "" CACHE PATH
  "Directory containing architecture-specific asm headers for the BPF build")

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)

add_subdirectory(src/lib)
add_subdirectory(src/daemon)
add_subdirectory(src/tools)
add_subdirectory(examples)
add_subdirectory(tests)
add_subdirectory(bpf)

install(TARGETS qaffinity EXPORT quic-affinityTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(TARGET qaffctl)
  install(TARGETS qaffctl RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
if(TARGET qaffd)
  install(TARGETS qaffd RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
endif()
if(TARGET qaff-agent)
  install(TARGETS qaff-agent RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
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

install(FILES README.md LICENSE
  DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(FILES
  docs/control-protocol.md
  docs/cid-index.md
  docs/fuzzing.md
  docs/integration-contract.md
  docs/state-store.md
  docs/worker-registry.md
  DESTINATION ${CMAKE_INSTALL_DOCDIR}/docs)

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

if(BUILD_TESTING AND TARGET qaff_bpf AND TARGET qaffd AND
   TARGET qaffctl AND TARGET qaff-agent)
  add_test(NAME packaging_smoke
    COMMAND /bin/sh
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_packaging_smoke.sh
      ${CMAKE_CURRENT_BINARY_DIR})
endif()

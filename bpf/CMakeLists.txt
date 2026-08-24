if(NOT QAFF_BUILD_BPF)
  return()
endif()

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
set(QAFF_BPF_OBJECT ${PROJECT_BINARY_DIR}/qaff_reuseport.bpf.o)
add_custom_command(
  OUTPUT ${QAFF_BPF_OBJECT}
  COMMAND ${CLANG_EXECUTABLE}
    -O2
    -g
    -target ${QAFF_BPF_CLANG_TARGET}
    -D__TARGET_ARCH_${QAFF_BPF_TARGET_ARCH}
    -DQAFF_BPF
    -I${PROJECT_SOURCE_DIR}/bpf
    -I${PROJECT_SOURCE_DIR}/include
    -I${PROJECT_SOURCE_DIR}/src/internal
    -I${QAFF_BPF_SYSTEM_INCLUDE_DIR}
    -c ${PROJECT_SOURCE_DIR}/bpf/qaff_reuseport.bpf.c
    -o ${QAFF_BPF_OBJECT}
  DEPENDS
    ${PROJECT_SOURCE_DIR}/bpf/qaff_reuseport.bpf.c
    ${PROJECT_SOURCE_DIR}/bpf/qaff_bpf.h
    ${PROJECT_SOURCE_DIR}/include/quic_affinity/types.h
    ${PROJECT_SOURCE_DIR}/src/internal/bpf_abi.h
  VERBATIM)

add_custom_target(qaff_bpf ALL DEPENDS ${QAFF_BPF_OBJECT})
install(FILES ${QAFF_BPF_OBJECT}
  DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/quic-affinity)

foreach(QAFF_BPF_DEPENDENT_TARGET IN ITEMS
    qaffd
    test_reuseport_smoke
    test_egress_parser
    test_qaffd_control
    test_qaffd_restart
    test_qaffd_egress)
  if(TARGET ${QAFF_BPF_DEPENDENT_TARGET})
    add_dependencies(${QAFF_BPF_DEPENDENT_TARGET} qaff_bpf)
  endif()
endforeach()

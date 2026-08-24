if(QAFF_BUILD_FUZZERS)
  if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR
      "QAFF_BUILD_FUZZERS requires Clang with libFuzzer support")
  endif()

  add_library(qaff_fuzz_support STATIC
    ${PROJECT_SOURCE_DIR}/src/lib/cid_profile.c
    ${PROJECT_SOURCE_DIR}/src/internal/control_protocol.c
    ${PROJECT_SOURCE_DIR}/src/internal/quic_parser.c)
  target_include_directories(qaff_fuzz_support PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src/internal)
  target_compile_options(qaff_fuzz_support PRIVATE
    -Wall -Wextra -Wpedantic
    -fno-omit-frame-pointer
    -fsanitize=fuzzer-no-link,address,undefined)

  function(qaff_add_fuzzer target source dictionary)
    add_executable(${target} ${source})
    target_link_libraries(${target} PRIVATE qaff_fuzz_support)
    target_compile_options(${target} PRIVATE
      -Wall -Wextra -Wpedantic
      -fno-omit-frame-pointer
      -fsanitize=fuzzer,address,undefined)
    target_link_options(${target} PRIVATE
      -fsanitize=fuzzer,address,undefined)
    if(BUILD_TESTING)
      add_test(NAME ${target}_smoke
        COMMAND /bin/sh
          ${CMAKE_CURRENT_SOURCE_DIR}/run_fuzz_smoke.sh
          $<TARGET_FILE:${target}>
          ${dictionary})
      set_tests_properties(${target}_smoke PROPERTIES
        LABELS fuzz
        TIMEOUT 120)
    endif()
  endfunction()

  qaff_add_fuzzer(fuzz_quic_parser
    fuzz/fuzz_quic_parser.c
    ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/quic_parser.dict)
  qaff_add_fuzzer(fuzz_cid_profile
    fuzz/fuzz_cid_profile.c
    ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/cid_profile.dict)
  qaff_add_fuzzer(fuzz_control_protocol
    fuzz/fuzz_control_protocol.c
    ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/control_protocol.dict)
endif()

if(NOT BUILD_TESTING)
  return()
endif()

function(qaff_add_unit target test_name library)
  add_executable(${target} ${target}.c)
  target_link_libraries(${target} PRIVATE ${library})
  target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
  add_test(NAME ${test_name} COMMAND $<TARGET_FILE:${target}>)
endfunction()

qaff_add_unit(test_quic_parser quic_parser qaffinity)
target_include_directories(test_quic_parser PRIVATE
  ${PROJECT_SOURCE_DIR}/src/internal)

qaff_add_unit(test_cid_profile cid_profile qaffinity)

qaff_add_unit(test_control_protocol control_protocol qaffinity)
target_include_directories(test_control_protocol PRIVATE
  ${PROJECT_SOURCE_DIR}/src/internal)

qaff_add_unit(test_qaffd_authorization qaffd_authorization
  qaffd_authorization)
qaff_add_unit(test_qaffd_state_store qaffd_state_store qaffd_state_store)
target_include_directories(test_qaffd_state_store PRIVATE
  ${PROJECT_SOURCE_DIR}/include)
qaff_add_unit(test_qaffd_worker_registry qaffd_worker_registry
  qaffd_worker_registry)
target_include_directories(test_qaffd_worker_registry PRIVATE
  ${PROJECT_SOURCE_DIR}/include)
qaff_add_unit(test_qaffd_cid_index qaffd_cid_index qaffd_cid_index)
target_include_directories(test_qaffd_cid_index PRIVATE
  ${PROJECT_SOURCE_DIR}/include)
qaff_add_unit(test_qaffd_cleanup_retry qaffd_cleanup_retry
  qaffd_cleanup_retry)

if(NOT QAFF_BUILD_BPF)
  return()
endif()

set(QAFF_BPF_OBJECT ${PROJECT_BINARY_DIR}/qaff_reuseport.bpf.o)

add_executable(test_reuseport_smoke test_reuseport_smoke.c)
target_include_directories(test_reuseport_smoke PRIVATE
  ${PROJECT_SOURCE_DIR}/src/internal)
target_link_libraries(test_reuseport_smoke PRIVATE qaffinity)
target_compile_options(test_reuseport_smoke PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME reuseport_smoke
  COMMAND /bin/sh
    ${CMAKE_CURRENT_SOURCE_DIR}/run_reuseport_smoke.sh
    $<TARGET_FILE:test_reuseport_smoke>
    ${QAFF_BPF_OBJECT})
set_tests_properties(reuseport_smoke PROPERTIES SKIP_RETURN_CODE 77)

add_executable(test_egress_parser test_egress_parser.c)
target_link_libraries(test_egress_parser PRIVATE qaffinity)
target_compile_options(test_egress_parser PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME egress_parser
  COMMAND /bin/sh
    ${CMAKE_CURRENT_SOURCE_DIR}/run_egress_parser.sh
    $<TARGET_FILE:test_egress_parser>
    ${QAFF_BPF_OBJECT})
set_tests_properties(egress_parser PROPERTIES SKIP_RETURN_CODE 77)

if(TARGET qaffd)
  add_executable(test_qaffd_control test_qaffd_control.c)
  target_link_libraries(test_qaffd_control PRIVATE qaffinity)
  target_compile_options(test_qaffd_control PRIVATE -Wall -Wextra -Wpedantic)
  add_test(NAME qaffd_control
    COMMAND /bin/sh
      ${CMAKE_CURRENT_SOURCE_DIR}/run_qaffd_control.sh
      $<TARGET_FILE:qaffd>
      $<TARGET_FILE:test_qaffd_control>
      ${QAFF_BPF_OBJECT})
  set_tests_properties(qaffd_control PROPERTIES
    SKIP_RETURN_CODE 77
    TIMEOUT 20)

  add_executable(test_qaffd_restart test_qaffd_restart.c)
  target_include_directories(test_qaffd_restart PRIVATE
    ${PROJECT_SOURCE_DIR}/src/internal)
  target_link_libraries(test_qaffd_restart PRIVATE qaffinity)
  target_compile_options(test_qaffd_restart PRIVATE -Wall -Wextra -Wpedantic)
  add_test(NAME qaffd_restart
    COMMAND /bin/sh
      ${CMAKE_CURRENT_SOURCE_DIR}/run_qaffd_restart.sh
      $<TARGET_FILE:qaffd>
      $<TARGET_FILE:test_qaffd_restart>
      ${QAFF_BPF_OBJECT})
  set_tests_properties(qaffd_restart PROPERTIES
    SKIP_RETURN_CODE 77
    TIMEOUT 20)

  add_executable(test_qaffd_egress test_qaffd_egress.c)
  target_link_libraries(test_qaffd_egress PRIVATE qaffinity)
  target_compile_options(test_qaffd_egress PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(TARGET qaffd AND TARGET qaffctl AND TARGET qaff-agent)
  add_executable(test_qaff_agent_target test_qaff_agent_target.c)
  target_compile_options(test_qaff_agent_target PRIVATE -Wall -Wextra -Wpedantic)
  add_test(NAME qaff_agent
    COMMAND /bin/sh
      ${CMAKE_CURRENT_SOURCE_DIR}/run_qaff_agent.sh
      $<TARGET_FILE:qaffd>
      $<TARGET_FILE:qaffctl>
      $<TARGET_FILE:qaff-agent>
      $<TARGET_FILE:test_qaff_agent_target>
      ${QAFF_BPF_OBJECT})
  set_tests_properties(qaff_agent PROPERTIES
    SKIP_RETURN_CODE 77
    TIMEOUT 20)
endif()

if(TARGET qaffd AND TARGET qaffctl)
  add_test(NAME qaffctl_control
    COMMAND /bin/sh
      ${CMAKE_CURRENT_SOURCE_DIR}/run_qaffctl_control.sh
      $<TARGET_FILE:qaffd>
      $<TARGET_FILE:qaffctl>
      ${QAFF_BPF_OBJECT})
  set_tests_properties(qaffctl_control PROPERTIES SKIP_RETURN_CODE 77)

  add_test(NAME egress_attach_smoke
    COMMAND /bin/sh
      ${CMAKE_CURRENT_SOURCE_DIR}/run_egress_attach_smoke.sh
      $<TARGET_FILE:qaffd>
      $<TARGET_FILE:qaffctl>
      ${QAFF_BPF_OBJECT})
  set_tests_properties(egress_attach_smoke PROPERTIES SKIP_RETURN_CODE 77)
endif()

if(TARGET qaffd AND TARGET qaffctl AND TARGET qaff_minimal_control)
  add_test(NAME minimal_control_example
    COMMAND /bin/sh
      ${CMAKE_CURRENT_SOURCE_DIR}/run_minimal_control_example.sh
      $<TARGET_FILE:qaffd>
      $<TARGET_FILE:qaffctl>
      $<TARGET_FILE:qaff_minimal_control>
      ${QAFF_BPF_OBJECT})
  set_tests_properties(minimal_control_example PROPERTIES SKIP_RETURN_CODE 77)
endif()

if(TARGET qaffd AND TARGET qaffctl AND TARGET test_qaffd_egress)
  add_test(NAME egress_learn_smoke
    COMMAND /bin/sh
      ${CMAKE_CURRENT_SOURCE_DIR}/run_egress_learn_smoke.sh
      $<TARGET_FILE:qaffd>
      $<TARGET_FILE:qaffctl>
      $<TARGET_FILE:test_qaffd_egress>
      ${QAFF_BPF_OBJECT})
  set_tests_properties(egress_learn_smoke PROPERTIES SKIP_RETURN_CODE 77)
endif()

if(TARGET qaffd AND TARGET qaffctl AND TARGET qaff_quiche_control_probe)
  add_test(NAME quiche_control_probe
    COMMAND /bin/sh
      ${CMAKE_CURRENT_SOURCE_DIR}/run_quiche_control_probe.sh
      $<TARGET_FILE:qaffd>
      $<TARGET_FILE:qaffctl>
      $<TARGET_FILE:qaff_quiche_control_probe>
      ${QAFF_BPF_OBJECT})
  set_tests_properties(quiche_control_probe PROPERTIES SKIP_RETURN_CODE 77)
endif()

if(TARGET qaffd AND TARGET qaffctl AND TARGET qaff_quiche_udp_smoke)
  set(QAFF_QUICHE_CERT_DIR
    ${PROJECT_SOURCE_DIR}/third_party/quiche/quiche/examples)
  add_test(NAME quiche_udp_smoke
    COMMAND /bin/sh
      ${CMAKE_CURRENT_SOURCE_DIR}/run_quiche_udp_smoke.sh
      $<TARGET_FILE:qaffd>
      $<TARGET_FILE:qaff_quiche_udp_smoke>
      ${QAFF_BPF_OBJECT}
      ${QAFF_QUICHE_CERT_DIR}/cert.crt
      ${QAFF_QUICHE_CERT_DIR}/cert.key)
  set_tests_properties(quiche_udp_smoke PROPERTIES SKIP_RETURN_CODE 77)

  add_test(NAME quiche_profile_smoke
    COMMAND /bin/sh
      ${CMAKE_CURRENT_SOURCE_DIR}/run_quiche_profile_smoke.sh
      $<TARGET_FILE:qaffd>
      $<TARGET_FILE:qaff_quiche_udp_smoke>
      ${QAFF_BPF_OBJECT}
      ${QAFF_QUICHE_CERT_DIR}/cert.crt
      ${QAFF_QUICHE_CERT_DIR}/cert.key)
  set_tests_properties(quiche_profile_smoke PROPERTIES SKIP_RETURN_CODE 77)

  add_test(NAME quiche_passive_egress_smoke
    COMMAND /bin/sh
      ${CMAKE_CURRENT_SOURCE_DIR}/run_quiche_passive_egress_smoke.sh
      $<TARGET_FILE:qaffd>
      $<TARGET_FILE:qaffctl>
      $<TARGET_FILE:qaff_quiche_udp_smoke>
      ${QAFF_BPF_OBJECT}
      ${QAFF_QUICHE_CERT_DIR}/cert.crt
      ${QAFF_QUICHE_CERT_DIR}/cert.key)
  set_tests_properties(quiche_passive_egress_smoke PROPERTIES
    SKIP_RETURN_CODE 77)

  if(TARGET qaff-agent AND TARGET qaff_quiche_blackbox)
    add_test(NAME quiche_agent_blackbox_smoke
      COMMAND /bin/sh
        ${CMAKE_CURRENT_SOURCE_DIR}/run_quiche_agent_blackbox_smoke.sh
        $<TARGET_FILE:qaffd>
        $<TARGET_FILE:qaffctl>
        $<TARGET_FILE:qaff-agent>
        $<TARGET_FILE:qaff_quiche_blackbox>
        ${QAFF_BPF_OBJECT}
        ${QAFF_QUICHE_CERT_DIR}/cert.crt
        ${QAFF_QUICHE_CERT_DIR}/cert.key)
    set_tests_properties(quiche_agent_blackbox_smoke PROPERTIES
      SKIP_RETURN_CODE 77
      TIMEOUT 20)
  endif()
endif()

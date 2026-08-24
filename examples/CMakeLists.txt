if(QAFF_BUILD_EXAMPLES)
  add_executable(qaff_minimal_registry minimal_registry/main.c)
  target_link_libraries(qaff_minimal_registry PRIVATE qaffinity)
  target_compile_options(qaff_minimal_registry PRIVATE
    -Wall -Wextra -Wpedantic)

  add_executable(qaff_minimal_control minimal_control/main.c)
  target_link_libraries(qaff_minimal_control PRIVATE qaffinity)
  target_compile_options(qaff_minimal_control PRIVATE
    -Wall -Wextra -Wpedantic)
endif()

set(QAFF_QUICHE_INCLUDE_DIR
  ${PROJECT_SOURCE_DIR}/third_party/quiche/quiche/include)
set(QAFF_QUICHE_LIBRARY
  ${PROJECT_SOURCE_DIR}/third_party/quiche/target/debug/libquiche.so)

if(QAFF_BUILD_EXAMPLES AND QAFF_BUILD_QUICHE_EXAMPLES AND
   EXISTS ${QAFF_QUICHE_INCLUDE_DIR}/quiche.h AND
   EXISTS ${QAFF_QUICHE_LIBRARY})
  add_executable(qaff_quiche_control_probe quiche_control_probe/main.c)
  target_include_directories(qaff_quiche_control_probe PRIVATE
    ${QAFF_QUICHE_INCLUDE_DIR})
  target_link_libraries(qaff_quiche_control_probe PRIVATE
    qaffinity
    ${QAFF_QUICHE_LIBRARY})
  set_target_properties(qaff_quiche_control_probe PROPERTIES
    BUILD_RPATH "$ORIGIN;${PROJECT_SOURCE_DIR}/third_party/quiche/target/debug")
  add_custom_command(TARGET qaff_quiche_control_probe POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E create_symlink
      ${QAFF_QUICHE_LIBRARY}
      $<TARGET_FILE_DIR:qaff_quiche_control_probe>/libquiche.so.0
    VERBATIM)
  target_compile_options(qaff_quiche_control_probe PRIVATE
    -Wall -Wextra -Wpedantic)

  add_executable(qaff_quiche_udp_smoke quiche_udp_smoke/main.c)
  target_include_directories(qaff_quiche_udp_smoke PRIVATE
    ${QAFF_QUICHE_INCLUDE_DIR})
  target_link_libraries(qaff_quiche_udp_smoke PRIVATE
    qaffinity
    ${QAFF_QUICHE_LIBRARY})
  set_target_properties(qaff_quiche_udp_smoke PROPERTIES
    BUILD_RPATH "$ORIGIN;${PROJECT_SOURCE_DIR}/third_party/quiche/target/debug")
  add_custom_command(TARGET qaff_quiche_udp_smoke POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E create_symlink
      ${QAFF_QUICHE_LIBRARY}
      $<TARGET_FILE_DIR:qaff_quiche_udp_smoke>/libquiche.so.0
    VERBATIM)
  target_compile_options(qaff_quiche_udp_smoke PRIVATE
    -Wall -Wextra -Wpedantic)
elseif(QAFF_BUILD_EXAMPLES AND QAFF_BUILD_QUICHE_EXAMPLES)
  message(STATUS
    "quiche integration example disabled; build quiche FFI under third_party/quiche to enable it")
endif()

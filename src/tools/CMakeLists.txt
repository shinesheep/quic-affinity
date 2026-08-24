if(QAFF_BUILD_TOOLS)
  add_executable(qaffctl qaffctl/main.c)
  target_include_directories(qaffctl PRIVATE
    ${PROJECT_SOURCE_DIR}/src/internal)
  target_link_libraries(qaffctl PRIVATE qaffinity)
  target_compile_definitions(qaffctl PRIVATE
    QAFF_PROJECT_VERSION="${PROJECT_VERSION}")
  target_compile_options(qaffctl PRIVATE -Wall -Wextra -Wpedantic)

  add_executable(qaff-agent qaff-agent/main.c)
  target_link_libraries(qaff-agent PRIVATE qaffinity)
  target_compile_options(qaff-agent PRIVATE -Wall -Wextra -Wpedantic)
endif()

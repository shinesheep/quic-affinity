if(QAFF_BUILD_DAEMON OR BUILD_TESTING)
  add_library(qaffd_authorization STATIC authorization.c)
  target_include_directories(qaffd_authorization PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR})
  target_compile_options(qaffd_authorization PRIVATE
    -Wall -Wextra -Wpedantic)

  add_library(qaffd_state_store STATIC state_store.c)
  target_include_directories(qaffd_state_store PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR})
  target_include_directories(qaffd_state_store PRIVATE
    ${PROJECT_SOURCE_DIR}/include)
  target_compile_options(qaffd_state_store PRIVATE
    -Wall -Wextra -Wpedantic)

  add_library(qaffd_worker_registry STATIC worker_registry.c)
  target_include_directories(qaffd_worker_registry PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR})
  target_include_directories(qaffd_worker_registry PRIVATE
    ${PROJECT_SOURCE_DIR}/include)
  target_link_libraries(qaffd_worker_registry PUBLIC qaffd_authorization)
  target_compile_options(qaffd_worker_registry PRIVATE
    -Wall -Wextra -Wpedantic)

  add_library(qaffd_cid_index STATIC cid_index.c)
  target_include_directories(qaffd_cid_index PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/src/internal)
  target_include_directories(qaffd_cid_index PRIVATE
    ${PROJECT_SOURCE_DIR}/include)
  target_compile_options(qaffd_cid_index PRIVATE
    -Wall -Wextra -Wpedantic)

  add_library(qaffd_cleanup_retry STATIC cleanup_retry.c)
  target_include_directories(qaffd_cleanup_retry PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR})
  target_compile_options(qaffd_cleanup_retry PRIVATE
    -Wall -Wextra -Wpedantic)
endif()

if(QAFF_BUILD_DAEMON)
  add_executable(qaffd main.c)
  target_link_libraries(qaffd PRIVATE
    qaffinity
    qaffd_authorization
    qaffd_cleanup_retry
    qaffd_cid_index
    qaffd_state_store
    qaffd_worker_registry)
  target_include_directories(qaffd PRIVATE
    ${PROJECT_SOURCE_DIR}/src/internal)
  target_compile_options(qaffd PRIVATE -Wall -Wextra -Wpedantic)
endif()

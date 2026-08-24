add_library(qaffinity
  cid_profile.c
  control_client.c
  ../internal/control_protocol.c
  bpf_loader.c
  qaffinity.c
  ../internal/quic_parser.c)

target_include_directories(qaffinity
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    ${PROJECT_SOURCE_DIR}/src/internal)

target_link_libraries(qaffinity
  PUBLIC
    PkgConfig::LIBBPF
    Threads::Threads)

target_compile_options(qaffinity PRIVATE -Wall -Wextra -Wpedantic)
add_library(quic-affinity::qaffinity ALIAS qaffinity)

cmake_minimum_required(VERSION 3.20)

project(qaff_consumer_smoke LANGUAGES C)

find_package(quic-affinity CONFIG REQUIRED)

add_executable(qaff_consumer_smoke main.c)
target_link_libraries(qaff_consumer_smoke PRIVATE quic-affinity::qaffinity)

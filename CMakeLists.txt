cmake_minimum_required(VERSION 3.20)

project(server)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin/)

file(GLOB_RECURSE src "${PROJECT_SOURCE_DIR}/src/*.cpp")
file(GLOB_RECURSE hdr "${PROJECT_SOURCE_DIR}/src/*.h")

add_executable(
	server
	${src}
	${hdr}
)

set_property(TARGET server PROPERTY CXX_STANDARD 20)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)


add_subdirectory(modules/libuv)
add_subdirectory(modules/mbedtls)
add_subdirectory(modules/spdlog)

target_include_directories(server PRIVATE "${PROJECT_SOURCE_DIR}/modules" "${PROJECT_SOURCE_DIR}/modules/mbedtls/include" "${PROJECT_SOURCE_DIR}/modules/libuv/include")
target_link_libraries(server PRIVATE uv_a spdlog mbedtls mbedcrypto mbedx509)
cmake_minimum_required(VERSION 3.14)
project(dslc CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)

# yaml-cpp
set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
set(YAML_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(yaml-cpp
    GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
    GIT_TAG 0.8.0
    GIT_SHALLOW TRUE
    GIT_PROGRESS TRUE)

# nlohmann_json
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
FetchContent_Declare(nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
    GIT_SHALLOW TRUE
    GIT_PROGRESS TRUE)

# inja is header-only: download it but skip its own CMake (it would want its own json setup)
FetchContent_Declare(inja
    GIT_REPOSITORY https://github.com/pantor/inja.git
    GIT_TAG v3.4.0
    GIT_SHALLOW TRUE
    GIT_PROGRESS TRUE
    SOURCE_SUBDIR does-not-exist)

FetchContent_MakeAvailable(yaml-cpp nlohmann_json inja)

add_executable(dslc main.cpp)
target_include_directories(dslc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${inja_SOURCE_DIR}/include)
target_link_libraries(dslc PRIVATE yaml-cpp::yaml-cpp nlohmann_json::nlohmann_json)
if(MSVC)
    target_compile_options(dslc PRIVATE /W3 /utf-8)
else()
    target_compile_options(dslc PRIVATE -Wall -Wextra)
endif()
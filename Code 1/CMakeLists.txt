cmake_minimum_required(VERSION 3.14)
project(dslc_v2 CXX)

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

FetchContent_MakeAvailable(yaml-cpp)

add_executable(dslc_v2 main.cpp)
target_include_directories(dslc_v2 PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/Parser
    ${CMAKE_CURRENT_SOURCE_DIR}/Analyzer
    ${CMAKE_CURRENT_SOURCE_DIR}/fields
)
target_link_libraries(dslc_v2 PRIVATE yaml-cpp::yaml-cpp)

if(MSVC)
    target_compile_options(dslc_v2 PRIVATE /W3 /utf-8)
else()
    target_compile_options(dslc_v2 PRIVATE -Wall -Wextra)
endif()

cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(bangr CXX C)

#find_package(Qt6 COMPONENTS Core Gui Widgets Required)

add_executable(${PROJECT_NAME}
    src/bangr.cpp
    src/functionAnalyze.cpp)

if(NOT BN_API_BUILD_EXAMPLES AND NOT BN_INTERNAL_BUILD)
    # Out-of-tree build
    find_path(
        BN_API_PATH
        NAMES binaryninjaapi.h
        HINTS ../.. binaryninjaapi $ENV{BN_API_PATH}
        REQUIRED
    )
    add_subdirectory(${BN_API_PATH} api)
endif()

#target_link_libraries(${PROJECT_NAME}
#    binaryninjaapi binaryninjaui Qt6::Core Qt6::Gui Qt6::Widgets)
target_link_libraries(${PROJECT_NAME}
    binaryninjaapi)

if (NOT WIN32)
    target_link_libraries(${PROJECT_NAME}
    dl)
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 20
    CXX_VISIBILITY_PRESET hidden
    CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin
    HEADLESS 1)

file(GLOB SOURCES "src/*.cpp")

add_library(Bangr SHARED ${SOURCES} ${MOCS})

set_target_properties(Bangr PROPERTIES
    CXX_STANDARD 20
    CXX_VISIBILITY_PRESET hidden
    CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin
    HEADLESS 1)

target_link_libraries(Bangr PUBLIC binaryninjaapi)
#target_link_libraries(Bangr PUBLIC binaryninjaapi binaryninjaui Qt6::Core Qt6::Gui Qt6::Widgets)

bn_install_plugin(Bangr)

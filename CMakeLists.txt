cmake_minimum_required(VERSION 3.5)

project(Drogon_JWT_Filter_Example)

file(GLOB_RECURSE sources CONFIGURE_DEPENDS src/*.c src/*.cc src/*.cpp src/*.hpp src/*.h)

include(CheckIncludeFileCXX)

check_include_file_cxx(any HAS_ANY)
check_include_file_cxx(string_view HAS_STRING_VIEW)
check_include_file_cxx(coroutine HAS_COROUTINE)

if (HAS_ANY AND HAS_STRING_VIEW AND HAS_COROUTINE)
    set(CMAKE_CXX_STANDARD 20)
elseif (HAS_ANY AND HAS_STRING_VIEW)
    set(CMAKE_CXX_STANDARD 17)
else ()
    set(CMAKE_CXX_STANDARD 14)
endif ()

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(${PROJECT_NAME} ${sources})

# ##############################################################################
add_subdirectory(libs/drogon)
add_subdirectory(libs/jwt-cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE drogon jwt-cpp)
# ##############################################################################

if (CMAKE_CXX_STANDARD LESS 17)
    # With C++14, use boost to support any and string_view
    message(STATUS "use c++14")
    find_package(Boost 1.61.0 REQUIRED)
    target_include_directories(${PROJECT_NAME} PRIVATE ${Boost_INCLUDE_DIRS})
elseif (CMAKE_CXX_STANDARD LESS 20)
    message(STATUS "use c++17")
else ()
    message(STATUS "use c++20")
endif ()

aux_source_directory(controllers CTL_SRC)
aux_source_directory(filters FILTER_SRC)
aux_source_directory(plugins PLUGIN_SRC)
aux_source_directory(models MODEL_SRC)

# Create views with namespaces.
drogon_create_views(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/views ${CMAKE_CURRENT_BINARY_DIR} TRUE)

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/models)
target_sources(${PROJECT_NAME} PRIVATE ${SRC_DIR} ${CTL_SRC} ${FILTER_SRC} ${PLUGIN_SRC} ${MODEL_SRC})
# ##############################################################################

# Dynamically loading views
#set_property(TARGET ${PROJECT_NAME} PROPERTY ENABLE_EXPORTS ON)

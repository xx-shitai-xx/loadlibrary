cmake_minimum_required(VERSION 3.17)
project(intercept CXX)

#set(CMAKE_DEBUG_POSTFIX _d)

set(BIN_DIR "bin" CACHE STRING "Binary output directory")


set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/${BIN_DIR})

# Second, for multi-config builds (e.g. msvc)
foreach( OUTPUTCONFIG ${CMAKE_CONFIGURATION_TYPES} )
	string( TOUPPER ${OUTPUTCONFIG} OUTPUTCONFIG )
	set( CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${PROJECT_SOURCE_DIR}/lib )
	set( CMAKE_LIBRARY_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${PROJECT_SOURCE_DIR}/lib )
	set( CMAKE_RUNTIME_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${PROJECT_SOURCE_DIR}/${BIN_DIR} )
endforeach( OUTPUTCONFIG CMAKE_CONFIGURATION_TYPES )

link_directories(${PROJECT_SOURCE_DIR}/lib)

# Adhere to GNU filesystem layout conventions
include(GNUInstallDirs)

# Lowercase project name for binaries and packaging
string(TOLOWER ${PROJECT_NAME} PROJECT_NAME_LOWER)

# Additional CMake modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/cmake)

# Version number in format X.YY.ZZ
set(VER_X 1)
set(VER_Y 0)
set(VER_Z 0)
set(VER_EXTRA "-beta" CACHE STRING "Extra version")

set(VER_FULL "${VER_X}.${VER_Y}.${VER_Z}${VER_EXTRA}")

STRING(REGEX REPLACE " " "-" VER_CPACK ${VER_FULL})

set(CMAKE_CXX_STANDARD 14)
file(GLOB PELOADER_SOURCES *.c *.h)

add_subdirectory(libdisasm)

add_library(${PROJECT_NAME} ${PELOADER_SOURCES})
add_dependencies(${PROJECT_NAME} disasm)


target_include_directories(${PROJECT_NAME} PUBLIC "./" "subhook/")
target_compile_definitions(${PROJECT_NAME} PRIVATE -D_GNU_SOURCE)
target_compile_options(${PROJECT_NAME} PRIVATE -march=native -O0 -ggdb3 -m32 -std=gnu99 -fshort-wchar -Wno-multichar -w )
target_link_libraries(${PROJECT_NAME} PRIVATE m disasm)
target_link_options(${PROJECT_NAME} PRIVATE -m32)

set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT ${PROJECT_NAME})

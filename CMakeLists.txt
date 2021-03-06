cmake_minimum_required(VERSION 3.17)
project(GraalEngine-loader C CXX)

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
set(BUILD_SHARED_LIBS FALSE CACHE BOOL "-" FORCE)

# Version number in format X.YY.ZZ
set(VER_X 1)
set(VER_Y 0)
set(VER_Z 0)
set(VER_EXTRA "-beta" CACHE STRING "Extra version")

set(VER_FULL "${VER_X}.${VER_Y}.${VER_Z}${VER_EXTRA}")

STRING(REGEX REPLACE " " "-" VER_CPACK ${VER_FULL})

set(CMAKE_CXX_STANDARD 14)

add_subdirectory(intercept)
add_subdirectory(peloader)

file(GLOB GSERVERNW_SOURCES mpclient.c )

add_executable(${PROJECT_NAME} ${GSERVERNW_SOURCES})

target_link_directories(${PROJECT_NAME} PRIVATE peloader/lib)

target_include_directories(${PROJECT_NAME} PRIVATE "include/" "intercept/" "intercept/subhook" "peloader/" "./")
target_compile_definitions(${PROJECT_NAME} PRIVATE -D_GNU_SOURCE)
target_compile_options(${PROJECT_NAME} PRIVATE -march=native -ggdb3 -m32 -std=gnu99 -fshort-wchar -Wno-multichar -mstackrealign)
target_link_libraries(${PROJECT_NAME} PUBLIC m intercept)
target_link_options(${PROJECT_NAME} PRIVATE -m32 -Wl,--dynamic-list=${PROJECT_SOURCE_DIR}/exports.lst -Wl,--whole-archive,${PROJECT_SOURCE_DIR}/peloader/lib/libpeloader.a,--no-whole-archive -march=native -ggdb3 -std=gnu99 -fshort-wchar -Wno-multichar -mstackrealign)
add_dependencies(${PROJECT_NAME} peloader intercept)

set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT ${PROJECT_NAME})

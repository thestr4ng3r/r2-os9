cmake_minimum_required(VERSION 3.2)

project(r2-os9)

set(CMAKE_C_STANDARD 99)

list(APPEND CMAKE_PREFIX_PATH "$ENV{HOME}/bin/prefix/radare2")
find_package(PkgConfig REQUIRED)
pkg_search_module(R_BIN REQUIRED r_bin)
pkg_search_module(R_ASM REQUIRED r_asm)

add_library(bin_os9 SHARED
		src/bin_os9.c)

set_target_properties(bin_os9 PROPERTIES PREFIX "")
target_include_directories(bin_os9 PUBLIC ${R_BIN_INCLUDE_DIRS})
target_link_libraries(bin_os9 ${R_BIN_LIBRARIES})


execute_process(COMMAND r2 -hh COMMAND grep LIBR_PLUGINS COMMAND awk "{print \$2}" OUTPUT_VARIABLE LIBR_PLUGINS)
set(PLUGINS_INSTALL_PATH "${LIBR_PLUGINS}" CACHE PATH "Path to install plugin libraries to.")

install(TARGETS bin_os9
		LIBRARY
		DESTINATION ${PLUGINS_INSTALL_PATH}
		NAMELINK_SKIP)

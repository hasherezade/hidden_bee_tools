cmake_minimum_required (VERSION 3.12)

# replace "project_template" by your own project name:
project ( bee_lvl1_parser )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

# include libpeconv headers:
include_directories ( ${PECONV_DIR}/include )

set (srcs
	bee.cpp
)

# general headers - they will be used for both EXE and DLL:
set (hdrs
	bee.h
)

# Choose to build the DLL or EXE
add_executable ( ${PROJECT_NAME} ${exe_hdrs} ${srcs} main.cpp )

# link with libpeconv.lib
target_link_libraries ( ${PROJECT_NAME} ${PECONV_LIB} )

#dependencies:
add_dependencies( ${PROJECT_NAME} libpeconv )

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )

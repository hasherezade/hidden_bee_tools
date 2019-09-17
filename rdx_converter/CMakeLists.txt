cmake_minimum_required (VERSION 2.8)

# replace "project_template" by your own project name:
project ( rdx_converter )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

# include libpeconv headers:
include_directories ( ${PECONV_DIR}/include )

set (srcs
	rdx.cpp
)

# general headers - they will be used for both EXE and DLL:
set (hdrs
	rdx.h
)

# Choose to build the DLL or EXE
add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} main.cpp )

# link with libpeconv.lib
target_link_libraries ( ${PROJECT_NAME} ${PECONV_LIB} )

#dependencies:
add_dependencies( ${PROJECT_NAME} libpeconv )

cmake_minimum_required (VERSION 3.12)

# replace "project_template" by your own project name:
project ( bee_lvl2_converter )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

# include libpeconv headers:
include_directories ( ${PECONV_DIR}/include )

set (srcs
	bee.cpp
	ns_exe.cpp
	rs_exe.cpp
	hs_exe.cpp
	xs_exe.cpp
)

# general headers - they will be used for both EXE and DLL:
set (hdrs
	bee.h
	ns_exe.h
	rs_exe.h
	hs_exe.h
	xs_exe.h
	util.h
)

# Choose to build the DLL or EXE
add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} main.cpp )

# link with libpeconv.lib
target_link_libraries ( ${PROJECT_NAME} ${PECONV_LIB} )

#dependencies:
add_dependencies( ${PROJECT_NAME} libpeconv )

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )

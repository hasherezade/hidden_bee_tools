cmake_minimum_required (VERSION 3.0)

# replace "project_template" by your own project name:
project ( loader )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (srcs
)

# general headers - they will be used for both EXE and DLL:
set (hdrs
)

# Choose to build the DLL or EXE
add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} main.cpp )

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )

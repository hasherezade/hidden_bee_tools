cmake_minimum_required ( VERSION 2.8 )

project ( hidden_bee_tools )

# libs
# modules:
set ( M_PARSER "libpeconv/libpeconv" )

# modules paths:
set (PECONV_DIR "${CMAKE_SOURCE_DIR}/${M_PARSER}" CACHE PATH "PEConv main path")
add_subdirectory ( ${PECONV_DIR} )
set ( PECONV_LIB $<TARGET_FILE:libpeconv> CACHE PATH "PEConvLib library path" )

# Add sub-directories
#
add_subdirectory ( bee_lvl1_parser )
add_subdirectory ( bee_lvl2_converter )
add_subdirectory ( rdx_converter )
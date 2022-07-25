cmake_minimum_required(VERSION 2.6.0)

project(RunTests)

# Supported options:
# -DFLEDGE_INCLUDE
# -DFLEDGE_LIB
# -DFLEDGE_SRC
# -DFLEDGE_INSTALL
#
# If no -D options are given and FLEDGE_ROOT environment variable is set
# then Fledge libraries and header files are pulled from FLEDGE_ROOT path.

set(CMAKE_CXX_FLAGS "-std=c++11 -O3")

# Generation version header file
set_source_files_properties(version.h PROPERTIES GENERATED TRUE)
add_custom_command(
  OUTPUT version.h
  DEPENDS ${CMAKE_SOURCE_DIR}/../VERSION
  COMMAND ${CMAKE_SOURCE_DIR}/../mkversion ${CMAKE_SOURCE_DIR}/..
  COMMENT "Generating version header"
  VERBATIM
)
include_directories(${CMAKE_BINARY_DIR})

# Set plugin type (south, north, filter)
set(PLUGIN_TYPE "south")

# Add here all needed Fledge libraries as list
set(NEEDED_FLEDGE_LIBS common-lib services-common-lib)

set(BOOST_COMPONENTS system thread)

find_package(Boost 1.53.0 COMPONENTS ${BOOST_COMPONENTS} REQUIRED)
include_directories(SYSTEM ${Boost_INCLUDE_DIR})

# Find source files
file(GLOB SOURCES ../*.cpp)
file(GLOB unittests "*.cpp")

# Find Fledge includes and libs, by including FindFledge.cmak file
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/..)
find_package(Fledge)
# If errors: make clean and remove Makefile
if (NOT FLEDGE_FOUND)
	if (EXISTS "${CMAKE_BINARY_DIR}/Makefile")
		execute_process(COMMAND make clean WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
		file(REMOVE "${CMAKE_BINARY_DIR}/Makefile")
	endif()
	# Stop the build process
	message(FATAL_ERROR "Fledge plugin '${PROJECT_NAME}' build error.")
endif()
# On success, FLEDGE_INCLUDE_DIRS and FLEDGE_LIB_DIRS variables are set 

# Find the S2OPC library source tree
if (NOT "$ENV{S2OPC}" STREQUAL "")
	set(OPCUADIR $ENV{S2OPC})
else()
	set(OPCUADIR "../S2OPC")
endif()
message("OPCUADIR: ${OPCUADIR}")

include_directories(/usr/local/include/s2opc/common)
include_directories(/usr/local/include/s2opc/clientserver)
include_directories(/usr/local/include/s2opc/clientserver/frontend)

# Add any plugin specific libraries

# Add S2OPC libraries
find_library(S2OPC_COMMON s2opc_common ${OPCUADIR}/build/lib)
if (NOT S2OPC_COMMON)
        message(FATAL_ERROR "S2OPC library s2opc_common not found.\n"
                        "Please build S2OPC library and set the environment variable S2OPC to library source tree root")
        return()
endif()

find_library(S2OPC_CLIENTSERVER s2opc_clientserver ${OPCUADIR}/build/lib)
if (NOT S2OPC_CLIENTSERVER)
        message(FATAL_ERROR "S2OPC library s2opc_clientserver not found.\n"
                        "Please build S2OPC library and set the environment variable S2OPC to library source tree root")
        return()
endif()

find_library(S2OPC_CLIENTWRAPPER s2opc_clientwrapper ${OPCUADIR}/build/lib)
if (NOT S2OPC_CLIENTWRAPPER)
        message(FATAL_ERROR "S2OPC library s2opc_clientwrapper not found.\n"
                        "Please build S2OPC library and set the environment variable S2OPC to library source tree root")
        return()
endif()

find_library(S2OPC_COMMONWRAPPER s2opc_commonwrapper ${OPCUADIR}/build/lib)
if (NOT S2OPC_COMMONWRAPPER)
        message(FATAL_ERROR "S2OPC library s2opc_commonwrapper not found.\n"
                        "Please build S2OPC library and set the environment variable S2OPC to library source tree root")
        return()
endif()


# Locate GTest
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

# Add ../include
include_directories(../include)
# Add Fledge include dir(s)
include_directories(${FLEDGE_INCLUDE_DIRS})

# Add other include paths

# Add Fledge lib path
link_directories(${FLEDGE_LIB_DIRS})

# Link runTests with what we want to test and the GTest and pthread library
add_executable(RunTests ${unittests} ${SOURCES} version.h)

# Add additional libraries

# Add additional link directories

set(FLEDGE_INSTALL "" CACHE INTERNAL "")
# Install library
if (FLEDGE_INSTALL)
	message(STATUS "Installing ${PROJECT_NAME} in ${FLEDGE_INSTALL}/plugins/${PLUGIN_TYPE}/${PROJECT_NAME}")
	install(TARGETS ${PROJECT_NAME} DESTINATION ${FLEDGE_INSTALL}/plugins/${PLUGIN_TYPE}/${PROJECT_NAME})
endif()

message("S2OPC_COMMON: ${S2OPC_COMMON}")
message("S2OPC_CLIENTSERVER: ${S2OPC_CLIENTSERVER}")
message("S2OPC_CLIENTWRAPPER: ${S2OPC_CLIENTWRAPPER}")
message("S2OPC_COMMONWRAPPER: ${S2OPC_COMMONWRAPPER}")

target_link_libraries(${PROJECT_NAME} ${S2OPC_COMMON} ${S2OPC_CLIENTSERVER} ${S2OPC_CLIENTWRAPPER} ${S2OPC_COMMONWRAPPER})

target_compile_options(${PROJECT_NAME} PRIVATE ${S2OPC_COMPILER_FLAGS})
target_compile_definitions(${PROJECT_NAME} PRIVATE ${S2OPC_DEFINITIONS})


target_link_libraries(RunTests ${GTEST_LIBRARIES} pthread)
target_link_libraries(RunTests ${NEEDED_FLEDGE_LIBS})
target_link_libraries(RunTests  ${Boost_LIBRARIES})
target_link_libraries(RunTests -lpthread -ldl)

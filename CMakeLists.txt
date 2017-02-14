# CMAKE + project name
cmake_minimum_required(VERSION 2.8.12)
project(OpensslCpp)

#set some variables
enable_testing()
set(CMAKE_AUTOMOC ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_AUTORCC ON)

#find the packages
find_package(Doxygen)

#Doxygen things
if(DOXYGEN_FOUND)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
add_custom_target(doc
  ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMENT "Generating API documentation with Doxygen" VERBATIM
)
endif(DOXYGEN_FOUND)

#conan usage
include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

#Recursively look for the src files
file(GLOB_RECURSE OpensslCpp_SOURCES "src/*.cpp")
file(GLOB_RECURSE OpensslCpp_HEADERS "src/*.hpp")
set (OpensslCpp_INCLUDE_DIRS "")
foreach (_headerFile ${OpensslCpp_HEADERS})
    get_filename_component(_dir ${_headerFile} PATH)
    list (APPEND OpensslCpp_INCLUDE_DIRS ${_dir})
endforeach()
list(REMOVE_DUPLICATES OpensslCpp_INCLUDE_DIRS)

file(GLOB_RECURSE untittest_OpensslCpp_SOURCES "test/*.cpp")

#include some directories
include_directories("./src")
include_directories(${OpensslCpp_INCLUDE_DIRS})

#compilation + linkage
#QT5_ADD_RESOURCES(OpensslCpp main.cpp ./src/resources.qrc)
add_library (OpensslCpp ${OpensslCpp_SOURCES})
target_compile_features(OpensslCpp PRIVATE cxx_range_for)
target_link_libraries(OpensslCpp ${CONAN_LIBS})

#Test folder
#add_executable (untittest_OpensslCpp ${untittest_OpensslCpp_SOURCES})
#target_link_libraries(untittest_OpensslCpp ${CONAN_LIBS})
#target_link_libraries(OpensslCpp Qt5::Widgets Qt5::Qml Qt5::Quick)
#add_test (UnitTest bin/untittest_OpensslCpp)

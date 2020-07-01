cmake_minimum_required(VERSION 3.16)
project(heaan_test)

set(CMAKE_CXX_STANDARD 17)
include_directories(usr/include)
include_directories(HEAAN/HEAAN/src)

file(GLOB HEAAN_SOURCE HEAAN/HEAAN/src/*.cpp)
file(GLOB NTL_SOURCE NTL/*.cpp)

list(REMOVE_ITEM HEAAN_SOURCE "HEAAN/HEAAN/src/HEAAN.cpp")

#add_library(ntl STATIC ${NTL_SOURCE})

add_executable(heaan_test main.cpp ${HEAAN_SOURCE} compare.hpp cipher.hpp crypyo.hpp context.hpp model.hpp)
target_link_libraries(heaan_test ${CMAKE_SOURCE_DIR}/usr/lib/ntl.a /usr/local/Cellar/gmp/6.2.0/lib/libgmp.a)

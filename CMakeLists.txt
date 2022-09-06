cmake_minimum_required(VERSION 2.8.12)


set(CMAKE_CXX_STANDARD 11)

#reduce the size
set(CMAKE_CXX_FLAGS "-g0")
#set(CMAKE_CXX_FLAGS "-g2")

SET(CMAKE_BUILD_TYPE "Release")
#SET(CMAKE_BUILD_TYPE "Debug")
set(PROJECT CryptoServer)

# Find includes in corresponding build directories
set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(HEADERS
    cryptoprocontroller.h
    configcontroller.h
    server.h
    connection.h
    protocol.h
    util.h
    )

set (SOURCES
    main.cpp
    cryptoprocontroller.cpp
    configcontroller.cpp
    server.cpp
    connection.cpp
    )

project(${PROJECT})

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR})
INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/include)

add_executable ( ${PROJECT} ${HEADERS} ${SOURCES} )

if(${CMAKE_SYSTEM_NAME} STREQUAL Windows)
    target_link_libraries(${PROJECT} User32 Advapi32 Crypt32 Bcrypt ws2_32.lib mswsock.lib PowrProf.lib Winmm.lib)
endif(${CMAKE_SYSTEM_NAME} STREQUAL Windows)

if(${CMAKE_SYSTEM_NAME} STREQUAL Linux)
    target_link_libraries (SIServer ${LIBS} pthread)
endif(${CMAKE_SYSTEM_NAME} STREQUAL Linux)

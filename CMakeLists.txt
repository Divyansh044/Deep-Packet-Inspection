cmake_minimum_required(VERSION 3.10)
project(DPI_Engine VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Find required packages
find_package(Threads REQUIRED)

# On Windows, handle libpcap/Npcap
if(WIN32)
    # Npcap SDK path - adjust if needed
    set(PCAP_INCLUDE_DIR "D:/npcap-sdk-1.16/Include" CACHE STRING "Path to Npcap include files")
    set(PCAP_LIBRARY "D:/npcap-sdk-1.16/Lib" CACHE STRING "Path to wpcap.lib")
else()
    # Unix/Linux
    find_package(PCAP REQUIRED)
    set(PCAP_INCLUDE_DIR ${PCAP_INCLUDE_DIR})
    set(PCAP_LIBRARY ${PCAP_LIBRARY})
endif()

include_directories(${PCAP_INCLUDE_DIR})

# Source files
set(SOURCES
    src/main.cpp
)

# Create executable
add_executable(dpi_engine ${SOURCES})

# Link libraries
target_link_libraries(dpi_engine PRIVATE 
    Threads::Threads
    ${PCAP_LIBRARY}
)

# Print configuration info
message(STATUS "DPI Engine Configuration:")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  PCAP Include: ${PCAP_INCLUDE_DIR}")
message(STATUS "  PCAP Library: ${PCAP_LIBRARY}")

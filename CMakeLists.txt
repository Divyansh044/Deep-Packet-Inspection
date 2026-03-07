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
    set(PCAP_LIBRARY "D:/npcap-sdk-1.16/Lib/x64/wpcap.lib" "D:/npcap-sdk-1.16/Lib/x64/Packet.lib" CACHE STRING "Paths to Npcap libraries")
    
    # Export compile commands so IntelliSense/clangd can find pcap.h
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
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
    src/packet_parser.cpp
    src/dns_parser.cpp
    src/http_parser.cpp
    src/tls_parser.cpp
    src/packet_capture.cpp
    src/policy_engine.cpp
)

# Create executable
add_executable(dpi_engine ${SOURCES})

# Link libraries
if(WIN32)
    target_link_libraries(dpi_engine PRIVATE 
        Threads::Threads
        ${PCAP_LIBRARY}
        ws2_32
    )
else()
    target_link_libraries(dpi_engine PRIVATE 
        Threads::Threads
        ${PCAP_LIBRARY}
    )
endif()

# Print configuration info
message(STATUS "DPI Engine Configuration:")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  PCAP Include: ${PCAP_INCLUDE_DIR}")
message(STATUS "  PCAP Library: ${PCAP_LIBRARY}")

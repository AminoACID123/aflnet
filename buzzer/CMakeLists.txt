cmake_minimum_required (VERSION 3.16.0)

project("Buzzer")

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

add_executable(buzzer virtual_controller.c)
file(GLOB TINYCRYPT_SRC ${CMAKE_SOURCE_DIR}/tinycrypt/lib/source/*.c)
add_library(tinycrypt STATIC ${TINYCRYPT_SRC})
target_include_directories(tinycrypt PUBLIC ${CMAKE_SOURCE_DIR}/tinycrypt/lib/include)

target_link_libraries(buzzer tinycrypt)

add_library(buzzer_socket SHARED buzzer_socket.c)
set_target_properties(buzzer_socket PROPERTIES COMPILE_FLAGS "-m32")
set_target_properties(buzzer_socket PROPERTIES LINK_FLAGS "-m32")
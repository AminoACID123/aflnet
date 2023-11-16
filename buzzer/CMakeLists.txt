cmake_minimum_required (VERSION 3.16.0)

project("Buzzer")

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

add_executable(buzzer virtual_controller.c)
target_link_directories(buzzer PRIVATE tinycrypt/lib)
target_include_directories(buzzer PRIVATE . tinycrypt/lib/include)
target_link_libraries(buzzer tinycrypt)

add_library(buzzer_socket SHARED buzzer_socket.c)
set_target_properties(buzzer_socket PROPERTIES COMPILE_FLAGS "-m32")
set_target_properties(buzzer_socket PROPERTIES LINK_FLAGS "-m32")
cmake_minimum_required(VERSION 3.10)
project(ndvm C)

add_custom_target(ndvm ALL
    COMMAND gcc -static ${CMAKE_CURRENT_LIST_DIR}/ndvm.c ${CMAKE_CURRENT_LIST_DIR}/vmcall.S -o ndvm
)

install(PROGRAMS ndvm DESTINATION bin)
#install(PROGRAMS init DESTINATION bin)

cmake_minimum_required(VERSION 3.10)
project(ndvm C)

add_executable(init init.c)
install(TARGETS init DESTINATION bin)

cmake_minimum_required(VERSION 3.10)
project(ndvm C)

add_executable(ndvm ndvm.c)
install(TARGETS ndvm DESTINATION bin)
#install(PROGRAMS init DESTINATION bin)

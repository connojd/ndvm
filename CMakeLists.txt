cmake_minimum_required(VERSION 3.10)
project(ndvm C)

add_executable(ndvm-client ndvm-client.c)
install(TARGETS ndvm-client DESTINATION bin)
install(PROGRAMS init DESTINATION bin)

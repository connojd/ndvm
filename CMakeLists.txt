cmake_minimum_required(VERSION 3.10)
project(ndvm C CXX)

enable_language(ASM)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_VERBOSE_MAKEFILE ON)

add_executable(ndvm ndvm.cpp vmcall.S)
target_compile_features(ndvm PRIVATE cxx_std_17)
target_compile_options(ndvm PRIVATE -mtune=generic -march=x86-64)

add_executable(fvm fvm.cpp vmcall.S)
target_compile_features(fvm PRIVATE cxx_std_17)
target_compile_options(fvm PRIVATE -mtune=generic -march=x86-64)

install(PROGRAMS ndvm DESTINATION bin)
install(PROGRAMS fvm DESTINATION bin)
#install(PROGRAMS init.sh DESTINATION bin)

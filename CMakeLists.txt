cmake_minimum_required(VERSION 3.6)
project(arcfour)

set(SOURCE_FILES main.c funcs.h)
add_executable(arcfour ${SOURCE_FILES})
cmake_minimum_required(VERSION 2.8)
project (STS)
add_executable (sts main.c server.c client.c common.c util.c)
target_link_libraries (sts ssl)


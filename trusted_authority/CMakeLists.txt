cmake_minimum_required(VERSION 3.5)
project(TRX_Trusted_Authority)

#FIXME properly download and link IB-ME
file(GLOB SOURCES ../../ibme/src/* ../../ibme/include/*)

add_library(ibme ${SOURCES})

target_include_directories(ibme PUBLIC ../../ibme/include)
target_link_libraries(ibme pbc gmp crypto)

add_executable(trx_ta trx_ta.c trx_ta.h)

target_link_libraries(trx_ta LINK_PUBLIC ibme)

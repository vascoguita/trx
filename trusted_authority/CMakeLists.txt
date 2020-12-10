cmake_minimum_required(VERSION 3.5)
project(TRX_Trusted_Authority)

include(ExternalProject)
ExternalProject_Add(
    project_ibme
    GIT_REPOSITORY https://github.com/vascoguita/IB-ME.git
    CMAKE_ARGS "-DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/ibme"
)

add_library(ibme STATIC IMPORTED)
set_property(TARGET ibme PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/ibme/lib/libibme.a)
add_dependencies(ibme project_ibme)

include_directories(${CMAKE_CURRENT_BINARY_DIR}/ibme/include/ibme)
add_executable(trx_ta trx_ta.c trx_ta.h)
target_link_libraries(trx_ta ibme pbc gmp crypto)
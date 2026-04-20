cmake_minimum_required(VERSION 3.16)
project(cp_abe_guo2023 C)

set(CMAKE_C_STANDARD 11)

find_package(OpenSSL REQUIRED)

find_path(PBC_INCLUDE_DIR pbc/pbc.h
  PATHS ${PBC_ROOT}/include /usr/include /usr/local/include
  PATH_SUFFIXES "")
find_library(PBC_LIBRARY NAMES pbc
  PATHS ${PBC_ROOT}/lib /usr/lib /usr/local/lib)

if(NOT PBC_INCLUDE_DIR OR NOT PBC_LIBRARY)
  message(FATAL_ERROR "PBC not found. Set PBC_ROOT to PBC install prefix, or install libpbc-dev.")
endif()

find_path(GMP_INCLUDE_DIR gmp.h)
find_library(GMP_LIBRARY NAMES gmp)

set(CP_ABE_SRC
  src/crypto_utils.c
  src/kek_tree.c
  src/lsss.c
  src/abe_core.c
  src/abe_io.c
  src/abe_state.c
  src/abe_ct_pack.c
)

add_executable(cp_abe_demo
  src/main.c
  ${CP_ABE_SRC}
)

add_executable(cp_abe_cli
  src/cli_cp_abe.c
  ${CP_ABE_SRC}
)

target_include_directories(cp_abe_demo PRIVATE ${PBC_INCLUDE_DIR} ${GMP_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(cp_abe_demo PRIVATE ${PBC_LIBRARY} ${GMP_LIBRARY} OpenSSL::Crypto)
if(WIN32)
  target_link_libraries(cp_abe_demo PRIVATE ws2_32)
endif()

target_include_directories(cp_abe_cli PRIVATE ${PBC_INCLUDE_DIR} ${GMP_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(cp_abe_cli PRIVATE ${PBC_LIBRARY} ${GMP_LIBRARY} OpenSSL::Crypto)
if(WIN32)
  target_link_libraries(cp_abe_cli PRIVATE ws2_32)
endif()

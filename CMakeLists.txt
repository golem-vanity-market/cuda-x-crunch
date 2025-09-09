
cmake_minimum_required(VERSION 3.22 FATAL_ERROR)
include(FetchContent)
set(SECP256K1_ECMULT_WINDOW_SIZE 17 CACHE STRING "Window size for ecmult precomputation")

FetchContent_Declare(
  secp256k1
  GIT_REPOSITORY https://github.com/scx1332/secp256k1.git
  GIT_TAG master
)
FetchContent_MakeAvailable(secp256k1)


project(profanity_cuda LANGUAGES CXX CUDA)

set(CMAKE_CXX_STANDARD 20)

# This entry is patched during production build. For debug build use only one architecture.
set(CMAKE_CUDA_ARCHITECTURES 86)

add_executable(profanity_cuda
  profanity.cu
  ArgParser.hpp
  private_key.cu
  private_key.h
  private_key_search.cpp
  bip32.h
  bip32_extras.cpp
  create3.cu
  create3search.cpp
  create3.h
  precomp.cpp
  precomp.hpp
  types.hpp
  utils.hpp
  utils.cpp
  debug_utils.hpp
  debug_utils.cpp
  scorer.cuh
  cpu_create3.cpp
  cpu_create3search.cpp
  cpu_scorer.h
  cpu_private_key.cpp
  cpu_private_key_search.cpp
  cpu_bip32_search.cpp
 )

 if(UNIX AND NOT APPLE)
     target_include_directories(profanity_cuda PRIVATE /usr/local/cuda/targets/x86_64-linux/include)
 endif()


target_link_libraries(profanity_cuda PRIVATE secp256k1)


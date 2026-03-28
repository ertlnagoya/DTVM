# Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_executable(dtvm dtvm.cpp)
target_link_libraries(dtvm PRIVATE dtvmcore CLI11::CLI11)

if(ZEN_ENABLE_EVM)
  target_link_libraries(dtvm PUBLIC evmc::evmc evmc::instructions)
  if(TARGET mcl::mclbn256)
    target_link_libraries(dtvm PRIVATE mcl::mclbn256)
  endif()
  if(TARGET c_kzg_4844)
    target_link_libraries(dtvm PRIVATE c_kzg_4844)
    target_compile_definitions(
      dtvm
      PRIVATE ZEN_C_KZG_TRUSTED_SETUP_PATH="${ZEN_C_KZG_TRUSTED_SETUP_PATH}"
    )
  endif()
endif()

if(ZEN_ENABLE_PROFILER)
  target_link_libraries(dtvm PRIVATE profiler)
endif()

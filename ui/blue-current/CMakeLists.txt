include(GNUInstallDirs)
if(NOT BUILD_DAEMON OR NOT BUILD_CLI OR NOT ENABLE_WALLET)
  message(FATAL_ERROR "Blue Current needs BUILD_DAEMON, BUILD_CLI and ENABLE_WALLET.")
endif()
find_program(BLUE_CURRENT_CABAL cabal REQUIRED)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(BLUE_CURRENT_BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/cabal" CACHE PATH "Blue Current Cabal build directory")
set(BLUE_CURRENT_STORE_DIR "" CACHE PATH "Optional shared Cabal store")
set(wallet_binary "${CMAKE_CURRENT_BINARY_DIR}/bin/elements-blue-current${CMAKE_EXECUTABLE_SUFFIX}")
file(GLOB_RECURSE wallet_sources CONFIGURE_DEPENDS app/* src/* cbits/* assets/*)
add_custom_command(OUTPUT "${wallet_binary}"
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/scripts/build.py"
    --cabal "${BLUE_CURRENT_CABAL}" --ghc "${ELEMENTS_GHC}"
    --build-dir "${BLUE_CURRENT_BUILD_DIR}" --store-dir "${BLUE_CURRENT_STORE_DIR}"
    --output "${wallet_binary}"
  DEPENDS ${wallet_sources} blue-current.cabal cabal.project scripts/build.py
  VERBATIM USES_TERMINAL)
add_custom_target(elements-blue-current ALL DEPENDS "${wallet_binary}")
install(PROGRAMS "${wallet_binary}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(DIRECTORY assets DESTINATION "${CMAKE_INSTALL_DATADIR}/elements-blue-current")
install(FILES README.md LICENSE DESTINATION "${CMAKE_INSTALL_DATADIR}/elements-blue-current")
if(BUILD_TESTS)
  add_test(NAME blue_current_bundle_policy
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_bundle.py")
endif()

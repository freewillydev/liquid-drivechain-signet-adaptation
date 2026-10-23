# Haskell owns the migrated rules; there is deliberately no C++ fallback.
if(CMAKE_CROSSCOMPILING OR WIN32)
  message(FATAL_ERROR "The Haskell FFI migration currently requires a native macOS/Linux GHC toolchain; cross/Windows packaging is not qualified yet.")
endif()
include("${CMAKE_CURRENT_SOURCE_DIR}/CheckCabal.cmake")
find_program(ELEMENTS_GHC ghc REQUIRED)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/BmmConstants.hs")
function(check_haskell_header path generator)
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/${path}")
  execute_process(COMMAND "${ELEMENTS_GHC}" -Wall -Werror -no-user-package-db -package-env -
    -hide-all-packages -package base "${CMAKE_CURRENT_SOURCE_DIR}/BmmConstants.hs"
    -e "putStr BmmConstants.${generator}"
    OUTPUT_VARIABLE expected COMMAND_ERROR_IS_FATAL ANY)
  file(READ "${CMAKE_CURRENT_SOURCE_DIR}/${path}" actual)
  if(NOT expected STREQUAL actual)
    message(FATAL_ERROR "Regenerate ${path} from BmmConstants.${generator}")
  endif()
endfunction()
check_haskell_header(resource_constants.h resourceHeader)
check_haskell_header(../simplicity/elements/primitiveJetCost.inc jetCostHeader)
check_haskell_header(../simplicity/elements/ecxPrivateE2ePrimitiveJetNode.inc privateJetHeader)
check_haskell_header(../simplicity/elements/drivechainPrimitiveJetNode.inc publicJetHeader)
check_haskell_header(../simplicity/include/simplicity/elements/policy_constants.h simplicityHeader)
set(bmm_constants_generator header)
set(bootstrap_constants_generator bootstrapHeader)
set(parent_rules_generator parentRulesHeader)
set(exchange_constants_generator exchangeHeader)
set(activation_constants_generator activationHeader)
set(rpc_security_constants_generator rpcSecurityHeader)
set(network_defaults_generator networkDefaultsHeader)
set(journal_constants_generator journalHeader)
set(pegin_identity_generator peginIdentityHeader)
set(wallet_rpc_generator walletRpcHeader)
foreach(name IN ITEMS bmm_constants bootstrap_constants parent_rules exchange_constants activation_constants rpc_security_constants network_defaults journal_constants pegin_identity wallet_rpc)
  execute_process(COMMAND "${ELEMENTS_GHC}" -Wall -Werror -no-user-package-db -package-env -
    -hide-all-packages -package base "${CMAKE_CURRENT_SOURCE_DIR}/BmmConstants.hs"
    -e "putStr BmmConstants.${${name}_generator}"
    OUTPUT_VARIABLE generated_header COMMAND_ERROR_IS_FATAL ANY)
  file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${name}.h" CONTENT "${generated_header}")
endforeach()
get_filename_component(ghc_bin "${ELEMENTS_GHC}" DIRECTORY)
find_program(ELEMENTS_GHC_PKG ghc-pkg HINTS "${ghc_bin}" REQUIRED)
execute_process(COMMAND "${ELEMENTS_GHC_PKG}" field rts include-dirs --simple-output
  OUTPUT_VARIABLE rts_includes OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
separate_arguments(rts_includes NATIVE_COMMAND "${rts_includes}")

include(GNUInstallDirs)
include(FetchContent)
if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()
FetchContent_Declare(operation_capabilities
  URL https://codeload.github.com/freewillydev/operation-capabilities/tar.gz/2f4bd8dd7baa5bc210b2620502da9e14f0f21347
  URL_HASH SHA256=a1a22c2fbdf7a091ac7c9b7729ada775a46cc26715dc4f6969ba3f23c0e53516)
FetchContent_MakeAvailable(operation_capabilities)
include(GrpcDependencies.cmake)
find_program(UTREEXO_CARGO cargo REQUIRED)
set(utreexo_dir "${CMAKE_CURRENT_SOURCE_DIR}/utreexo-rs")
install(FILES "${utreexo_dir}/NOTICE" DESTINATION "${CMAKE_INSTALL_DOCDIR}/licenses"
  RENAME rustreexo-NOTICE)
set(utreexo_archive "${CMAKE_CURRENT_BINARY_DIR}/utreexo-target/release/libelements_utreexo_ffi.a")
add_custom_command(OUTPUT "${utreexo_archive}"
  COMMAND "${CMAKE_COMMAND}" -E env "CARGO_BUILD_JOBS=1"
    "${UTREEXO_CARGO}" build --release --locked --manifest-path "${utreexo_dir}/Cargo.toml"
    --target-dir "${CMAKE_CURRENT_BINARY_DIR}/utreexo-target"
  DEPENDS "${utreexo_dir}/Cargo.toml" "${utreexo_dir}/Cargo.lock" "${utreexo_dir}/src/lib.rs" VERBATIM)
add_custom_target(elements_utreexo_build DEPENDS "${utreexo_archive}")
add_library(elements_utreexo STATIC IMPORTED GLOBAL)
set_target_properties(elements_utreexo PROPERTIES IMPORTED_LOCATION "${utreexo_archive}")
add_dependencies(elements_utreexo elements_utreexo_build)
set(operation_sources
  "${operation_capabilities_SOURCE_DIR}/src/Control/Operation.hs"
  "${operation_capabilities_SOURCE_DIR}/src/Control/Operation/Validation.hs")

set(hs_library "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}elements_haskell${CMAKE_SHARED_LIBRARY_SUFFIX}")
set(hs_link_flags)
foreach(lib IN LISTS CMAKE_DL_LIBS)
  list(APPEND hs_link_flags "-optl-l${lib}")
endforeach()
if(APPLE)
  list(APPEND hs_link_flags "-optl-Wl,-install_name,@rpath/libelements_haskell.dylib")
  if(CMAKE_OSX_DEPLOYMENT_TARGET)
    foreach(phase c a l)
      list(APPEND hs_link_flags "-opt${phase}-mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}")
    endforeach()
  endif()
endif()
configure_file(runtime.c runtime.c COPYONLY)
add_custom_command(OUTPUT "${hs_library}" "${CMAKE_CURRENT_BINARY_DIR}/Drivechain_stub.h" "${CMAKE_CURRENT_BINARY_DIR}/DomainABI_stub.h" "${CMAKE_CURRENT_BINARY_DIR}/GrpcClient_stub.h"
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/generate_abi.py" --check
  COMMAND ${grpc_exec} "${ELEMENTS_GHC}" -O2 -Wall -Werror -fforce-recomp -dynamic -shared -fPIC -threaded -flink-rts
    -no-hs-main -no-user-package-db -hide-all-packages -package base -package bytestring -package transformers
    -package grpc-haskell-core -package grpc-haskell -package proto3-suite -package async -package text -package vector -package containers -package deepseq -package aeson
    "-i${CMAKE_CURRENT_SOURCE_DIR}" "-i${operation_capabilities_SOURCE_DIR}/src"
    "-i${grpc_generated}"
    -odir "${CMAKE_CURRENT_BINARY_DIR}" -hidir "${CMAKE_CURRENT_BINARY_DIR}"
    -stubdir "${CMAKE_CURRENT_BINARY_DIR}" ${hs_link_flags}
    "${CMAKE_CURRENT_SOURCE_DIR}/DomainABI.hs" "${CMAKE_CURRENT_SOURCE_DIR}/GrpcClient.hs" "${CMAKE_CURRENT_SOURCE_DIR}/Utreexo.hs" "${CMAKE_CURRENT_BINARY_DIR}/runtime.c" -o "${hs_library}"
  DEPENDS ${grpc_ready} Utreexo.hs GrpcClient.hs EnforcerCodec.hs Abi.hs DomainABI.hs domain_abi.h abi.def generate_abi.py Drivechain.hs Withdrawal.hs Deposit.hs Bmm.hs BmmConstants.hs ParentReplay.hs Exchange.hs Usdd.hs ScriptPolicy.hs CapabilityContext.hs Workflow.hs ${operation_sources} runtime.c VERBATIM)
add_custom_target(elements_haskell_build DEPENDS "${hs_library}" "${CMAKE_CURRENT_BINARY_DIR}/Drivechain_stub.h" "${CMAKE_CURRENT_BINARY_DIR}/DomainABI_stub.h")
add_library(elements_haskell_runtime SHARED IMPORTED GLOBAL)
set_target_properties(elements_haskell_runtime PROPERTIES IMPORTED_LOCATION "${hs_library}")
add_dependencies(elements_haskell_runtime elements_haskell_build)
add_library(elements_haskell STATIC bridge.cpp simplicity_bridge.cpp grpc_bridge.cpp)
set_target_properties(elements_haskell PROPERTIES POSITION_INDEPENDENT_CODE ON OUTPUT_NAME elements_haskell_bridge)
add_dependencies(elements_haskell elements_haskell_build)
target_include_directories(elements_haskell PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_include_directories(elements_haskell SYSTEM PRIVATE ${rts_includes})
target_link_libraries(elements_haskell PUBLIC elements_haskell_runtime elements_utreexo PRIVATE core_interface bitcoin_consensus bitcoin_util)
if(BUILD_TESTS)
  add_test(NAME haskell_cabal_version COMMAND "${CMAKE_COMMAND}"
    "-DTEST_TMP=${CMAKE_CURRENT_BINARY_DIR}/cabal-version-test"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/test/cabal_check.cmake")
  add_executable(haskell_grpc_probe EXCLUDE_FROM_ALL test/grpc_probe.cpp)
  target_link_libraries(haskell_grpc_probe PRIVATE elements_haskell core_interface)
  set_target_properties(haskell_grpc_probe PROPERTIES SKIP_BUILD_RPATH FALSE BUILD_RPATH "${CMAKE_CURRENT_BINARY_DIR}")
endif()

if(APPLE)
  find_program(hs_install_name_tool install_name_tool REQUIRED)
  find_program(hs_otool otool REQUIRED)
  find_program(hs_codesign codesign REQUIRED)
else()
  find_program(hs_patchelf patchelf REQUIRED)
endif()
configure_file(BundleRuntime.cmake.in BundleRuntime.cmake @ONLY)
# Component installs (including libconsensus alone) need the same runtime.
install(SCRIPT "${CMAKE_CURRENT_BINARY_DIR}/BundleRuntime.cmake" ALL_COMPONENTS)
install(TARGETS elements_haskell ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT elementsconsensus)

if(BUILD_TESTS)
  find_program(ELEMENTS_BASH bash REQUIRED)
  add_test(NAME haskell_capability_types COMMAND "${CMAKE_COMMAND}" -E env
    "GHC=${ELEMENTS_GHC}" "TMPDIR=${CMAKE_CURRENT_BINARY_DIR}"
    "${ELEMENTS_BASH}" "${operation_capabilities_SOURCE_DIR}/test/check-capabilities.sh")
  add_executable(test_haskell_ffi ffi_tests.cpp)
  target_include_directories(test_haskell_ffi PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
  target_include_directories(test_haskell_ffi SYSTEM PRIVATE ${rts_includes})
  target_link_libraries(test_haskell_ffi PRIVATE elements_haskell core_interface)
  add_test(NAME haskell_ffi_parity COMMAND test_haskell_ffi)
  set_tests_properties(haskell_ffi_parity PROPERTIES TIMEOUT 60)
  add_executable(test_haskell_loader loader_tests.cpp)
  target_link_libraries(test_haskell_loader PRIVATE core_interface ${CMAKE_DL_LIBS})
  add_dependencies(test_haskell_loader elements_haskell_build)
  add_test(NAME haskell_runtime_reload COMMAND test_haskell_loader "${hs_library}")
  add_executable(test_haskell_domain_abi domain_abi_tests.cpp)
  add_dependencies(test_haskell_domain_abi elements_haskell_build)
  target_include_directories(test_haskell_domain_abi PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
  target_include_directories(test_haskell_domain_abi SYSTEM PRIVATE ${rts_includes})
  target_link_libraries(test_haskell_domain_abi PRIVATE elements_haskell core_interface)
  add_test(NAME haskell_domain_abi COMMAND test_haskell_domain_abi)
endif()

# Native C-core transport with typed protobuf codecs, never a grpcurl subprocess.
# ELEMENTS_CABAL is selected and checked before dependency downloads.
find_program(ELEMENTS_PATCH patch REQUIRED)
find_path(ELEMENTS_GRPC_INCLUDE grpc/grpc.h REQUIRED)
find_path(ELEMENTS_GRPC_CPP_INCLUDE grpcpp/version_info.h REQUIRED)
find_library(ELEMENTS_GRPC_LIBRARY grpc REQUIRED)
get_filename_component(ELEMENTS_GRPC_LIBDIR "${ELEMENTS_GRPC_LIBRARY}" DIRECTORY)
find_path(ELEMENTS_PROTO_INCLUDE google/protobuf/wrappers.proto REQUIRED)
FetchContent_Declare(grpc_haskell
  URL https://codeload.github.com/awakesecurity/gRPC-haskell/tar.gz/0e16723da9cb54c28b9efdb11ca5da968890c5af
  URL_HASH SHA256=1d4c8af56b206604eecc5eff5af647645f9ff90fcb859dd0e1101798d61a9084
  PATCH_COMMAND "${ELEMENTS_PATCH}" -p1 -i "${CMAKE_CURRENT_SOURCE_DIR}/grpc-channel-options.patch")
FetchContent_Declare(proto3_suite
  URL https://codeload.github.com/awakesecurity/proto3-suite/tar.gz/bb987ad2421ce429401193e1bf0416fe79625836
  URL_HASH SHA256=091072f36870becf1d402a0f32c302b16afb125d0aa750261f04c5f2dc5035dc)
FetchContent_MakeAvailable(grpc_haskell proto3_suite)
configure_file(grpc.project.in grpc.project @ONLY)
configure_file(grpc.project.freeze grpc.project.freeze COPYONLY)
set(grpc_project "${CMAKE_CURRENT_BINARY_DIR}/grpc.project")
set(grpc_build "${CMAKE_CURRENT_BINARY_DIR}/grpc-build" CACHE PATH "Cabal build artifacts for direct enforcer gRPC")
set(grpc_generated "${CMAKE_CURRENT_BINARY_DIR}/enforcer-generated")
set(grpc_proto "${CMAKE_CURRENT_SOURCE_DIR}/enforcer-proto")
file(GLOB_RECURSE grpc_schemas CONFIGURE_DEPENDS "${grpc_proto}/*.proto")
set(grpc_ready "${CMAKE_CURRENT_BINARY_DIR}/grpc-ready")
add_custom_command(OUTPUT "${grpc_ready}"
  COMMAND "${ELEMENTS_CABAL}" build grpc-haskell-core grpc-haskell:lib:grpc-haskell proto3-suite:exe:compile-proto-file
    "--project-file=${grpc_project}" "--builddir=${grpc_build}" -j1
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${grpc_generated}"
  COMMAND "${CMAKE_COMMAND}" "-DCABAL=${ELEMENTS_CABAL}" "-DPROJECT=${grpc_project}"
    "-DBUILD=${grpc_build}" "-DPROTO=${grpc_proto}" "-DGOOGLE=${ELEMENTS_PROTO_INCLUDE}"
    "-DOUTPUT=${grpc_generated}" -P "${CMAKE_CURRENT_SOURCE_DIR}/GenerateEnforcer.cmake"
  COMMAND "${CMAKE_COMMAND}" -E touch "${grpc_ready}"
  DEPENDS ${grpc_schemas} "${grpc_project}" "${CMAKE_CURRENT_BINARY_DIR}/grpc.project.freeze" grpc-channel-options.patch GenerateEnforcer.cmake
  VERBATIM)
set(grpc_exec "${ELEMENTS_CABAL}" exec "--project-file=${grpc_project}" "--builddir=${grpc_build}" --)

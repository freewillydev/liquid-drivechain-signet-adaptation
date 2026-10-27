# Preserve the fork's public C ABI after upstream's removal of libconsensus.
include(GNUInstallDirs)

add_library(elementsconsensus_objects OBJECT
  script/bitcoinconsensus.cpp
  util/strencodings.cpp
  util/moneystr.cpp
  util/check.cpp
)
target_compile_definitions(elementsconsensus_objects PRIVATE BUILD_BITCOIN_INTERNAL)
target_link_libraries(elementsconsensus_objects PRIVATE core_interface bitcoin_consensus)

foreach(kind IN ITEMS SHARED STATIC)
  if(kind STREQUAL "SHARED")
    set(target elementsconsensus)
  else()
    set(target elementsconsensus_static)
  endif()
  add_library(${target} ${kind}
    $<TARGET_OBJECTS:elementsconsensus_objects>
    $<TARGET_OBJECTS:bitcoin_consensus>
    $<TARGET_OBJECTS:bitcoin_crypto>
    $<TARGET_OBJECTS:bitcoin_clientversion>
    $<TARGET_OBJECTS:elementssimplicity>
  )
  set_target_properties(${target} PROPERTIES OUTPUT_NAME elementsconsensus)
  target_link_libraries(${target} PRIVATE core_interface secp256k1 elements_haskell)
  if(BUILD_TESTS)
    add_executable(test_consensus_reader_${kind} haskell/test/consensus_reader_tests.cpp)
    target_include_directories(test_consensus_reader_${kind} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/script)
    target_link_libraries(test_consensus_reader_${kind} PRIVATE ${target} core_interface)
    add_test(NAME consensus_reader_${kind} COMMAND test_consensus_reader_${kind})
  endif()
  install(TARGETS ${target}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT elementsconsensus
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT elementsconsensus
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT elementsconsensus
  )
endforeach()
set_target_properties(elementsconsensus PROPERTIES VERSION 0.0.0 SOVERSION 0
  ARCHIVE_OUTPUT_NAME elementsconsensus_import)

install(FILES script/bitcoinconsensus.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  COMPONENT elementsconsensus)
install(FILES $<TARGET_FILE:secp256k1> DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RENAME ${CMAKE_STATIC_LIBRARY_PREFIX}elements-secp256k1${CMAKE_STATIC_LIBRARY_SUFFIX}
  COMPONENT elementsconsensus)

set(consensus_private_libs "-lelements-secp256k1 -lelements_haskell")
if(APPLE)
  string(APPEND consensus_private_libs " -Wl,-dead_strip -lc++")
elseif(NOT MSVC)
  string(APPEND consensus_private_libs " -lstdc++ -lm")
endif()
set(prefix "\${pcfiledir}/../..")
set(exec_prefix "\${prefix}")
set(libdir "\${prefix}/${CMAKE_INSTALL_LIBDIR}")
set(includedir "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
set(PACKAGE_NAME Elements)
set(PACKAGE_VERSION ${PROJECT_VERSION})
set(ELEMENTS_CONSENSUS_PRIVATE_LIBS "${consensus_private_libs}")
configure_file(${PROJECT_SOURCE_DIR}/libbitcoinconsensus.pc.in libelementsconsensus.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libelementsconsensus.pc
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig COMPONENT elementsconsensus)

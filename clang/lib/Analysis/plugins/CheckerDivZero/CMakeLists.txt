include_directories( ${CMAKE_CURRENT_SOURCE_DIR}/../../../StaticAnalyzer/Checkers )

set(LLVM_LINK_COMPONENTS
  Support
  )

set(LLVM_EXPORTED_SYMBOL_FILE ${CMAKE_CURRENT_SOURCE_DIR}/DivZeroCheckerPlugin.exports)
add_llvm_library(DivZeroCheckerPlugin MODULE BUILDTREE_ONLY DivZeroChecker.cpp PLUGIN_TOOL clang)

clang_target_link_libraries(DivZeroCheckerPlugin PRIVATE
  clangAnalysis
  clangAST
  clangStaticAnalyzerCore
  clangStaticAnalyzerFrontend
 )

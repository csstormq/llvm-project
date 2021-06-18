set(LLVM_LINK_COMPONENTS
  Support
  )

set(LLVM_EXPORTED_SYMBOL_FILE ${CMAKE_CURRENT_SOURCE_DIR}/MallocCheckerPlugin.exports)
add_llvm_library(MallocCheckerPlugin MODULE BUILDTREE_ONLY MallocChecker.cpp PLUGIN_TOOL clang)

clang_target_link_libraries(MallocCheckerPlugin PRIVATE
  clangAnalysis
  clangAST
  clangStaticAnalyzerCore
  clangStaticAnalyzerFrontend
  )

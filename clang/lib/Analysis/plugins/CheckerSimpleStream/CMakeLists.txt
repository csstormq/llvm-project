set(LLVM_LINK_COMPONENTS
  Support
  )

set(LLVM_EXPORTED_SYMBOL_FILE ${CMAKE_CURRENT_SOURCE_DIR}/SimpleStreamCheckerPlugin.exports)
add_llvm_library(SimpleStreamCheckerPlugin MODULE BUILDTREE_ONLY SimpleStreamChecker.cpp PLUGIN_TOOL clang)

clang_target_link_libraries(SimpleStreamCheckerPlugin PRIVATE
  clangAnalysis
  clangAST
  clangStaticAnalyzerCore
  clangStaticAnalyzerFrontend
  )

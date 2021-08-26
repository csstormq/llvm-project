set(LLVM_LINK_COMPONENTS
  Support
  )

set(LLVM_EXPORTED_SYMBOL_FILE ${CMAKE_CURRENT_SOURCE_DIR}/ArrayBoundCheckerPlugin.exports)
add_llvm_library(ArrayBoundCheckerPlugin MODULE BUILDTREE_ONLY ArrayBoundChecker.cpp PLUGIN_TOOL clang)

clang_target_link_libraries(ArrayBoundCheckerPlugin PRIVATE
  clangAnalysis
  clangAST
  clangStaticAnalyzerCore
  clangStaticAnalyzerFrontend
  )

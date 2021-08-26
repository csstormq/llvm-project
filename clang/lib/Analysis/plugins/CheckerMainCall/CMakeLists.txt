set(LLVM_LINK_COMPONENTS
  Support
  )

set(LLVM_EXPORTED_SYMBOL_FILE ${CMAKE_CURRENT_SOURCE_DIR}/MainCallCheckerPlugin.exports)
add_llvm_library(MainCallCheckerPlugin MODULE BUILDTREE_ONLY MainCallChecker.cpp PLUGIN_TOOL clang)

clang_target_link_libraries(MainCallCheckerPlugin PRIVATE
  clangAnalysis
  clangAST
  clangStaticAnalyzerCore
  clangStaticAnalyzerFrontend
  )

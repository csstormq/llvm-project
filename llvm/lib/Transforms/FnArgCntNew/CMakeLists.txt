add_llvm_component_library(LLVMFnArgCntNew
  FnArgCntNew.cpp

  DEPENDS
  intrinsics_gen

  LINK_COMPONENTS
  Core
  Support
  )

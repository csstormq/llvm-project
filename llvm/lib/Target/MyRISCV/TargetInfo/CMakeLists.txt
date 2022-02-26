add_llvm_component_library(LLVMMyRISCVInfo
  MyRISCVTargetInfo.cpp

  LINK_COMPONENTS
  Support

  ADD_TO_COMPONENT
  MyRISCV
)

add_llvm_component_library(LLVMMyRISCVDesc
  MyRISCVMCTargetDesc.cpp
  MyRISCVMCAsmInfo.cpp
  MyRISCVInstPrinter.cpp

  LINK_COMPONENTS
  MC
  MyRISCVInfo
  Support

  ADD_TO_COMPONENT
  MyRISCV
)
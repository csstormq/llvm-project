add_llvm_component_group(MyRISCV)

set(sources
  MyRISCVTargetMachine.cpp
)

add_llvm_target(MyRISCVCodeGen ${sources}
  ADD_TO_COMPONENT
  MyRISCV
)

add_subdirectory(MCTargetDesc)
add_subdirectory(TargetInfo)

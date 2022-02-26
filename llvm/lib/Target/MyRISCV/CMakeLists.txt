add_llvm_component_group(MyRISCV)

set(LLVM_TARGET_DEFINITIONS MyRISCV.td)

tablegen(LLVM MyRISCVGenAsmWriter.inc -gen-asm-writer)
tablegen(LLVM MyRISCVGenCallingConv.inc -gen-callingconv)
tablegen(LLVM MyRISCVGenDAGISel.inc -gen-dag-isel)
tablegen(LLVM MyRISCVGenInstrInfo.inc -gen-instr-info)
tablegen(LLVM MyRISCVGenMCPseudoLowering.inc -gen-pseudo-lowering)
tablegen(LLVM MyRISCVGenRegisterInfo.inc -gen-register-info)
tablegen(LLVM MyRISCVGenSubtargetInfo.inc -gen-subtarget)

add_public_tablegen_target(MyRISCVCommonTableGen)

set(sources
  MyRISCVTargetMachine.cpp
  MyRISCVISelDAGToDAG.cpp
  MyRISCVAsmPrinter.cpp
  MyRISCVSubtarget.cpp
  MyRISCVISelLowering.cpp
  MyRISCVFrameLowering.cpp
  MyRISCVInstrInfo.cpp
  MyRISCVRegisterInfo.cpp
  MyRISCVMCInstLower.cpp
)

add_llvm_target(MyRISCVCodeGen ${sources}
  LINK_COMPONENTS
  AsmPrinter
  Core
  CodeGen
  MC
  MyRISCVDesc
  MyRISCVInfo
  SelectionDAG
  Support
  Target

  ADD_TO_COMPONENT
  MyRISCV
)

add_subdirectory(MCTargetDesc)
add_subdirectory(TargetInfo)

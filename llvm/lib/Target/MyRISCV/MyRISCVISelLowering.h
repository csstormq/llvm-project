#ifndef LLVM_LIB_TARGET_MYRISCV_MYRISCVISELLOWERING_H
#define LLVM_LIB_TARGET_MYRISCV_MYRISCVISELLOWERING_H

#include "llvm/CodeGen/SelectionDAG.h"
#include "llvm/CodeGen/TargetLowering.h"

namespace llvm {

class MyRISCVSubtarget;
class MyRISCVTargetMachine;

namespace MyRISCVISD {

enum NodeType {
  FIRST_NUMBER = ISD::BUILTIN_OP_END,
  RET_FLAG,
};

} // // end namespace MyRISCVISD

class MyRISCVTargetLowering : public TargetLowering {
  const MyRISCVSubtarget &Subtarget;

public:
  explicit MyRISCVTargetLowering(MyRISCVTargetMachine &TM);

  const char *getTargetNodeName(unsigned Opcode) const override;

  SDValue LowerFormalArguments(SDValue Chain, CallingConv::ID CallConv,
                               bool IsVarArg,
                               const SmallVectorImpl<ISD::InputArg> &Ins,
                               const SDLoc &DL, SelectionDAG &DAG,
                               SmallVectorImpl<SDValue> &InVals) const override;

  SDValue LowerReturn(SDValue Chain, CallingConv::ID CallConv, bool IsVarArg,
                      const SmallVectorImpl<ISD::OutputArg> &Outs,
                      const SmallVectorImpl<SDValue> &OutVals, const SDLoc &DL,
                      SelectionDAG &DAG) const override;
};

} // end namespace llvm

#endif  // LLVM_LIB_TARGET_MYRISCV_MYRISCVISELLOWERING_H

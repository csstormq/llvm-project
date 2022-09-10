#include "MyRISCVISelLowering.h"
#include "MCTargetDesc/MyRISCVMCTargetDesc.h"
#include "MyRISCVSubtarget.h"
#include "MyRISCVTargetMachine.h"
#include "llvm/CodeGen/CallingConvLower.h"

using namespace llvm;

#include "MyRISCVGenCallingConv.inc"

MyRISCVTargetLowering::MyRISCVTargetLowering(MyRISCVTargetMachine &TM)
    : TargetLowering(TM), Subtarget(*TM.getSubtargetImpl()) {
  addRegisterClass(MVT::i32, &MyRISCV::GPRRegClass);
  addRegisterClass(MVT::f32, &MyRISCV::FPR32RegClass);
  computeRegisterProperties(Subtarget.getRegisterInfo());
}

const char *MyRISCVTargetLowering::getTargetNodeName(unsigned Opcode) const {
  switch (Opcode) {
  case MyRISCVISD::RET_FLAG:
    return "MyRISCVISD::RET_FLAG";
  default:
    return nullptr;
  }
}

SDValue MyRISCVTargetLowering::LowerFormalArguments(
    SDValue Chain, CallingConv::ID CallConv, bool IsVarArg,
    const SmallVectorImpl<ISD::InputArg> &Ins, const SDLoc &DL,
    SelectionDAG &DAG, SmallVectorImpl<SDValue> &InVals) const {
  MachineFunction &MF = DAG.getMachineFunction();
  MachineRegisterInfo &MRI = MF.getRegInfo();

  SmallVector<CCValAssign, 16> ArgLocs;
  CCState CCInfo(CallConv, IsVarArg, MF, ArgLocs, *DAG.getContext());
  CCInfo.AnalyzeFormalArguments(Ins, CC_MyRISCV);

  for (unsigned i = 0, e = ArgLocs.size(); i < e; ++i) {
    CCValAssign &VA = ArgLocs[i];
    if (VA.getValVT() == MVT::f32) {
      const TargetRegisterClass *FPR32 = &MyRISCV::FPR32RegClass;
      Register VReg = MRI.createVirtualRegister(FPR32);
      MRI.addLiveIn(VA.getLocReg(), VReg);
      InVals.push_back(DAG.getCopyFromReg(Chain, DL, VReg, VA.getValVT()));
    }
  }

  return Chain;
}

SDValue
MyRISCVTargetLowering::LowerReturn(SDValue Chain, CallingConv::ID CallConv,
                                   bool IsVarArg,
                                   const SmallVectorImpl<ISD::OutputArg> &Outs,
                                   const SmallVectorImpl<SDValue> &OutVals,
                                   const SDLoc &DL, SelectionDAG &DAG) const {
  SmallVector<CCValAssign, 16> RVLocs;

  CCState CCInfo(CallConv, IsVarArg, DAG.getMachineFunction(), RVLocs,
                 *DAG.getContext());
  CCInfo.AnalyzeReturn(Outs, RetCC_MyRISCV);

  SDValue Glue;
  SmallVector<SDValue, 4> RetOps(1, Chain);

  for (unsigned i = 0, e = RVLocs.size(); i < e; ++i) {
    CCValAssign &VA = RVLocs[i];
    assert(VA.isRegLoc() && "Can only return in registers!");
    Chain = DAG.getCopyToReg(Chain, DL, VA.getLocReg(), OutVals[i], Glue);
    Glue = Chain.getValue(1);
    RetOps.push_back(DAG.getRegister(VA.getLocReg(), VA.getLocVT()));
  }

  RetOps[0] = Chain;

  if (Glue.getNode()) {
    RetOps.push_back(Glue);
  }

  return DAG.getNode(MyRISCVISD::RET_FLAG, DL, MVT::Other, RetOps);
}

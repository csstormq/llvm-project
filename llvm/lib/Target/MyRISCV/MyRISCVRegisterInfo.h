#ifndef LLVM_LIB_TARGET_MYRISCV_MYRISCVREGISTERINFO_H
#define LLVM_LIB_TARGET_MYRISCV_MYRISCVREGISTERINFO_H

#include "llvm/CodeGen/TargetRegisterInfo.h"

#define GET_REGINFO_HEADER
#include "MyRISCVGenRegisterInfo.inc"

namespace llvm {

class MyRISCVRegisterInfo : public MyRISCVGenRegisterInfo {
public:
  explicit MyRISCVRegisterInfo(unsigned HwMode);

  const MCPhysReg *getCalleeSavedRegs(const MachineFunction *MF) const override;

  BitVector getReservedRegs(const MachineFunction &MF) const override;

  void eliminateFrameIndex(MachineBasicBlock::iterator MI, int SPAdj,
                           unsigned FIOperandNum,
                           RegScavenger *RS = nullptr) const override;

  Register getFrameRegister(const MachineFunction &MF) const override;
};

} // end namespace llvm

#endif  // LLVM_LIB_TARGET_MYRISCV_MYRISCVREGISTERINFO_H

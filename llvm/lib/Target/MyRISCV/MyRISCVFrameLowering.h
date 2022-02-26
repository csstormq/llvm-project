#ifndef LLVM_LIB_TARGET_MYRISCV_MYRISCVFRAMELOWERING_H
#define LLVM_LIB_TARGET_MYRISCV_MYRISCVFRAMELOWERING_H

#include "llvm/CodeGen/TargetFrameLowering.h"

namespace llvm {

class MyRISCVSubtarget;

class MyRISCVFrameLowering : public TargetFrameLowering {
  const MyRISCVSubtarget &STI;

public:
  explicit MyRISCVFrameLowering(const MyRISCVSubtarget &STI)
      : TargetFrameLowering(StackGrowsDown,
                            /*StackAlignment=*/Align(16),
                            /*LocalAreaOffset=*/0),
        STI(STI) {}

  void emitPrologue(MachineFunction &MF, MachineBasicBlock &MBB) const override;

  void emitEpilogue(MachineFunction &MF, MachineBasicBlock &MBB) const override;

  bool hasFP(const MachineFunction &MF) const override;
};

} // end namespace llvm

#endif  // LLVM_LIB_TARGET_MYRISCV_MYRISCVFRAMELOWERING_H

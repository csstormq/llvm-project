#include "MyRISCVFrameLowering.h"
#include "llvm/CodeGen/MachineFunction.h"

using namespace llvm;

void MyRISCVFrameLowering::emitPrologue(MachineFunction &MF,
                                        MachineBasicBlock &MBB) const {
}

void MyRISCVFrameLowering::emitEpilogue(MachineFunction &MF,
                                        MachineBasicBlock &MBB) const {
}

bool MyRISCVFrameLowering::hasFP(const MachineFunction &MF) const {
  return false;
}

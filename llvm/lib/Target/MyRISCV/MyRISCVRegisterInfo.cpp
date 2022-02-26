#include "MyRISCVRegisterInfo.h"
#include "MyRISCVSubtarget.h"
#include "MyRISCVFrameLowering.h"
#include "MCTargetDesc/MyRISCVMCTargetDesc.h"
#include "llvm/CodeGen/MachineFunction.h"

#define GET_REGINFO_TARGET_DESC
#include "MyRISCVGenRegisterInfo.inc"

using namespace llvm;

MyRISCVRegisterInfo::MyRISCVRegisterInfo(unsigned HwMode)
    : MyRISCVGenRegisterInfo(MyRISCV::X1, /*DwarfFlavour*/ 0, /*EHFlavor*/ 0,
                             /*PC*/ 0, HwMode) {}

const MCPhysReg *
MyRISCVRegisterInfo::getCalleeSavedRegs(const MachineFunction *MF) const {
  return CC_Save_SaveList;
}

BitVector MyRISCVRegisterInfo::getReservedRegs(const MachineFunction &MF) const {
  BitVector Reserved(getNumRegs());
  Reserved.set(MyRISCV::X0);
  Reserved.set(MyRISCV::X2);
  Reserved.set(MyRISCV::X3);
  Reserved.set(MyRISCV::X4);
  return Reserved;
}

void MyRISCVRegisterInfo::eliminateFrameIndex(MachineBasicBlock::iterator MI,
                                              int SPAdj, unsigned FIOperandNum,
                                              RegScavenger *RS) const {
}

Register MyRISCVRegisterInfo::getFrameRegister(const MachineFunction &MF) const {
  return MyRISCV::X8;
}

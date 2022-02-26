#ifndef LLVM_LIB_TARGET_MYRISCV_MYRISCVSUBTARGET_H
#define LLVM_LIB_TARGET_MYRISCV_MYRISCVSUBTARGET_H

#include "MyRISCVISelLowering.h"
#include "MyRISCVFrameLowering.h"
#include "MyRISCVInstrInfo.h"
#include "MyRISCVRegisterInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"

#define GET_SUBTARGETINFO_HEADER
#include "MyRISCVGenSubtargetInfo.inc"

namespace llvm {

class MyRISCVTargetMachine;

class MyRISCVSubtarget : public MyRISCVGenSubtargetInfo {
  MyRISCVTargetLowering TLInfo;
  MyRISCVFrameLowering FrameLowering;
  MyRISCVInstrInfo InstrInfo;
  MyRISCVRegisterInfo RegInfo;

public:
  MyRISCVSubtarget(const Triple &TT, StringRef CPU, StringRef TuneCPU,
                   StringRef FS, MyRISCVTargetMachine &TM);

  const MyRISCVTargetLowering *getTargetLowering() const override {
    return &TLInfo;
  }

  const MyRISCVFrameLowering *getFrameLowering() const override {
    return &FrameLowering;
  }

  const MyRISCVInstrInfo *getInstrInfo() const override { return &InstrInfo; }

  const MyRISCVRegisterInfo *getRegisterInfo() const override { return &RegInfo; }

private:
  void ParseSubtargetFeatures(StringRef CPU, StringRef TuneCPU, StringRef FS);

  MyRISCVSubtarget &initializeSubtargetDependencies(const Triple &TT,
                                                    StringRef CPU,
                                                    StringRef FS);
};

} // end namespace llvm

#endif  // LLVM_LIB_TARGET_MYRISCV_MYRISCVSUBTARGET_H

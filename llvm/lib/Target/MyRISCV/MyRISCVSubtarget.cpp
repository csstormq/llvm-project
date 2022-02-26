#include "MyRISCVSubtarget.h"
#include "MyRISCVTargetMachine.h"

using namespace llvm;

#define DEBUG_TYPE "riscv-subtarget"

#define GET_SUBTARGETINFO_MC_DESC
#define GET_SUBTARGETINFO_TARGET_DESC
#define GET_SUBTARGETINFO_CTOR
#include "MyRISCVGenSubtargetInfo.inc"

MyRISCVSubtarget::MyRISCVSubtarget(const Triple &TT, StringRef CPU,
                                   StringRef TuneCPU, StringRef FS,
                                   MyRISCVTargetMachine &TM)
    : MyRISCVGenSubtargetInfo(TT, CPU, TuneCPU, FS), TLInfo(TM),
      FrameLowering(initializeSubtargetDependencies(TT, CPU, FS)),
      InstrInfo(*this), RegInfo(getHwMode()) {
}

MyRISCVSubtarget &
MyRISCVSubtarget::initializeSubtargetDependencies(const Triple &TT,
                                                  StringRef CPU,
                                                  StringRef FS) {
  if (CPU.empty()) {
    assert(TT.isArch32Bit() && "Only RV32 is currently supported!");
    CPU = "generic-rv32";
  }
  ParseSubtargetFeatures(CPU, CPU, FS);
  return *this;
}

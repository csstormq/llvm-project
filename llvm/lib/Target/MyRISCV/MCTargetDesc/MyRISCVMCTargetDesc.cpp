#include "MyRISCVMCTargetDesc.h"
#include "MyRISCVMCAsmInfo.h"
#include "MyRISCVInstPrinter.h"
#include "TargetInfo/MyRISCVTargetInfo.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/Support/TargetRegistry.h"

#define GET_INSTRINFO_MC_DESC
#include "MyRISCVGenInstrInfo.inc"

#define GET_REGINFO_MC_DESC
#include "MyRISCVGenRegisterInfo.inc"

#define GET_SUBTARGETINFO_MC_DESC
#include "MyRISCVGenSubtargetInfo.inc"

using namespace llvm;

namespace {

MCInstrInfo *createMyRISCVMCInstrInfo() {
  MCInstrInfo *X = new MCInstrInfo();
  InitMyRISCVMCInstrInfo(X);
  return X;
}

MCRegisterInfo *createMyRISCVMCRegisterInfo(const Triple &TT) {
  MCRegisterInfo *X = new MCRegisterInfo();
  InitMyRISCVMCRegisterInfo(X, MyRISCV::X1);
  return X;
}

MCAsmInfo *createMyRISCVMCAsmInfo(const MCRegisterInfo &MRI, const Triple &TT,
                                  const MCTargetOptions &Options) {
  return new MyRISCVMCAsmInfo(TT);
}

MCSubtargetInfo *createMyRISCVMCSubtargetInfo(const Triple &TT,
                                              StringRef CPU, StringRef FS) {
  if (CPU.empty()) {
    assert(TT.isArch32Bit() && "Only RV32 is currently supported!");
    CPU = "generic-rv32";
  }
  return createMyRISCVMCSubtargetInfoImpl(TT, CPU, CPU, FS);
}

MCInstPrinter *createMyRISCVMCInstPrinter(const Triple &T,
                                          unsigned SyntaxVariant,
                                          const MCAsmInfo &MAI,
                                          const MCInstrInfo &MII,
                                          const MCRegisterInfo &MRI) {
  return new MyRISCVInstPrinter(MAI, MII, MRI);
}

} // end anonymous namespace

extern "C" LLVM_EXTERNAL_VISIBILITY void LLVMInitializeMyRISCVTargetMC() {
  Target &RV32 = getMyRISCV32Target();
  TargetRegistry::RegisterMCAsmInfo(RV32, createMyRISCVMCAsmInfo);
  TargetRegistry::RegisterMCInstrInfo(RV32, createMyRISCVMCInstrInfo);
  TargetRegistry::RegisterMCRegInfo(RV32, createMyRISCVMCRegisterInfo);
  TargetRegistry::RegisterMCSubtargetInfo(RV32, createMyRISCVMCSubtargetInfo);
  TargetRegistry::RegisterMCInstPrinter(RV32, createMyRISCVMCInstPrinter);
}

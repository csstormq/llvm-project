#ifndef LLVM_LIB_TARGET_MYRISCV_MYRISCVTARGETMACHINE_H
#define LLVM_LIB_TARGET_MYRISCV_MYRISCVTARGETMACHINE_H

#include "llvm/Target/TargetMachine.h"
#include "MyRISCVSubtarget.h"

namespace llvm {

class MyRISCVTargetMachine : public LLVMTargetMachine {
  MyRISCVSubtarget Subtarget;
  std::unique_ptr<TargetLoweringObjectFile> TLOF;

public:
  MyRISCVTargetMachine(const Target &T, const Triple &TT, StringRef CPU,
                       StringRef FS, const TargetOptions &Options,
                       Optional<Reloc::Model> RM, Optional<CodeModel::Model> CM,
                       CodeGenOpt::Level OL, bool JIT);

  const MyRISCVSubtarget *getSubtargetImpl(const Function &F) const override {
    return &Subtarget;
  }

  const MyRISCVSubtarget *getSubtargetImpl() const { return &Subtarget; }

  TargetPassConfig *createPassConfig(PassManagerBase &PM) override;

  TargetLoweringObjectFile *getObjFileLowering() const override {
    return TLOF.get();
  }
};

} // end namespace llvm

#endif  // LLVM_LIB_TARGET_MYRISCV_MYRISCVTARGETMACHINE_H

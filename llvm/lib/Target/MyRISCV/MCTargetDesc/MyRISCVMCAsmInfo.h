#ifndef LLVM_LIB_TARGET_MYRISCV_MCTARGETDESC_MYRISCVMCASMINFO_H
#define LLVM_LIB_TARGET_MYRISCV_MCTARGETDESC_MYRISCVMCASMINFO_H

#include "llvm/MC/MCAsmInfoELF.h"

namespace llvm {

class Triple;

class MyRISCVMCAsmInfo : public MCAsmInfoELF {
public:
  explicit MyRISCVMCAsmInfo(const Triple &TT);
};

} // end namespace llvm

#endif // LLVM_LIB_TARGET_MYRISCV_MCTARGETDESC_MYRISCVMCASMINFO_H

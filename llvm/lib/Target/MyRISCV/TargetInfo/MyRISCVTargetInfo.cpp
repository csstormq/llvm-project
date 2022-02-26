#include "TargetInfo/MyRISCVTargetInfo.h"
#include "llvm/Support/TargetRegistry.h"

using namespace llvm;

namespace llvm {

Target &getMyRISCV32Target() {
  static Target MyRISCV32Target;
  return MyRISCV32Target;
}

} // end namespace llvm

extern "C" LLVM_EXTERNAL_VISIBILITY void LLVMInitializeMyRISCVTargetInfo() {
  RegisterTarget<Triple::myriscv32> X(getMyRISCV32Target(), "myriscv32",
                                      "32-bit RISC-V", "RISCV");
}

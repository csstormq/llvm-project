#ifndef LLVM_LIB_TARGET_MYRISCV_MYRISCV_H
#define LLVM_LIB_TARGET_MYRISCV_MYRISCV_H

namespace llvm {

class MyRISCVTargetMachine;
class FunctionPass;

FunctionPass *createMyRISCVISelDag(MyRISCVTargetMachine &TM);

} // end namespace llvm

#endif  // LLVM_LIB_TARGET_MYRISCV_MYRISCV_H

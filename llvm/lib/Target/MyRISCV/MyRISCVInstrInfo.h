#ifndef LLVM_LIB_TARGET_MYRISCV_MYRISCVINSTRINFO_H
#define LLVM_LIB_TARGET_MYRISCV_MYRISCVINSTRINFO_H

#include "llvm/CodeGen/TargetInstrInfo.h"

#define GET_INSTRINFO_HEADER
#include "MyRISCVGenInstrInfo.inc"

namespace llvm {

class MyRISCVSubtarget;

class MyRISCVInstrInfo : public MyRISCVGenInstrInfo {
  const MyRISCVSubtarget &STI;

public:
  explicit MyRISCVInstrInfo(MyRISCVSubtarget &STI);
};

} // end namespace llvm

#endif  // LLVM_LIB_TARGET_MYRISCV_MYRISCVINSTRINFO_H

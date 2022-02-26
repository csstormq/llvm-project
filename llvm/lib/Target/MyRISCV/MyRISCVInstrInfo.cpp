#include "MyRISCVInstrInfo.h"
#include "MyRISCVSubtarget.h"
#include "MCTargetDesc/MyRISCVMCTargetDesc.h"

using namespace llvm;

#define GET_INSTRINFO_CTOR_DTOR
#include "MyRISCVGenInstrInfo.inc"

MyRISCVInstrInfo::MyRISCVInstrInfo(MyRISCVSubtarget &STI)
    : MyRISCVGenInstrInfo(), STI(STI) {}

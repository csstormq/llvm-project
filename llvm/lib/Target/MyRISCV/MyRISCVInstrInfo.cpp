#include "MyRISCVInstrInfo.h"
#include "MCTargetDesc/MyRISCVMCTargetDesc.h"
#include "MyRISCVSubtarget.h"

using namespace llvm;

#define GET_INSTRINFO_CTOR_DTOR
#include "MyRISCVGenInstrInfo.inc"

MyRISCVInstrInfo::MyRISCVInstrInfo(MyRISCVSubtarget &STI)
    : MyRISCVGenInstrInfo(), STI(STI) {}

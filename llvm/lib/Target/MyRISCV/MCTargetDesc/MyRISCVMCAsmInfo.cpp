#include "MyRISCVMCAsmInfo.h"
#include "llvm/ADT/Triple.h"

using namespace llvm;

MyRISCVMCAsmInfo::MyRISCVMCAsmInfo(const Triple &TT) {
  assert(TT.isArch32Bit() && "Only RV32 is currently supported!");
  CodePointerSize = CalleeSaveStackSlotSize = TT.isArch32Bit() ? 4 : 4;
  CommentString = "#";
  Data16bitsDirective = "\t.half\t";
  Data32bitsDirective = "\t.word\t";
}

#include "MyRISCVInstPrinter.h"
#include "MCTargetDesc/MyRISCVMCTargetDesc.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/Support/FormattedStream.h"

using namespace llvm;

#define PRINT_ALIAS_INSTR
#include "MyRISCVGenAsmWriter.inc"

void MyRISCVInstPrinter::printInst(const MCInst *MI, uint64_t Address,
                                   StringRef Annot, const MCSubtargetInfo &STI,
                                   raw_ostream &OS) {
  if (!printAliasInstr(MI, Address, OS)) {
    printInstruction(MI, Address, OS);
  }
}

void MyRISCVInstPrinter::printOperand(const MCInst *MI, unsigned OpNo,
                                      raw_ostream &OS) {
  const MCOperand &MO = MI->getOperand(OpNo);

  if (MO.isReg()) {
    OS << getRegisterName(MO.getReg(), MyRISCV::ABIRegAltName);
    return;
  }

  if (MO.isImm()) {
    OS << MO.getImm();
    return;
  }

  assert(MO.isExpr() && "Unknown operand kind in printOperand!");
  MO.getExpr()->print(OS, &MAI);
}

#ifndef LLVM_LIB_TARGET_MYRISCV_MYRISCVMCINSTLOWER_H
#define LLVM_LIB_TARGET_MYRISCV_MYRISCVMCINSTLOWER_H

namespace llvm {

class MCContext;
class AsmPrinter;
class MachineInstr;
class MachineOperand;
class MCInst;
class MCOperand;

class MyRISCVMCInstLower {
  MCContext &Ctx;
  AsmPrinter &Printer;

public:
  MyRISCVMCInstLower(MCContext &Ctx, AsmPrinter &Printer);

  void Lower(const MachineInstr *MI, MCInst &OutMI) const;

private:
  bool LowerOperand(const MachineOperand &MO, MCOperand &MCOp) const;
};

} // end namespace llvm

#endif  // LLVM_LIB_TARGET_MYRISCV_MYRISCVMCINSTLOWER_H

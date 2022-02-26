#include "TargetInfo/MyRISCVTargetInfo.h"
#include "MCTargetDesc/MyRISCVMCTargetDesc.h"
#include "MyRISCVMCInstLower.h"
#include "llvm/CodeGen/AsmPrinter.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/Support/TargetRegistry.h"

using namespace llvm;

namespace {

class MyRISCVAsmPrinter : public AsmPrinter {
  MyRISCVMCInstLower MCInstLowering;

public:
  MyRISCVAsmPrinter(TargetMachine &TM, std::unique_ptr<MCStreamer> Streamer)
      : AsmPrinter(TM, std::move(Streamer)), MCInstLowering(OutContext, *this) {}

  void emitInstruction(const MachineInstr *MI) override;

private:
  bool emitPseudoExpansionLowering(MCStreamer &OutStreamer,
                                   const MachineInstr *MI);
};

} // end anonymous namespace

#include "MyRISCVGenMCPseudoLowering.inc"

void MyRISCVAsmPrinter::emitInstruction(const MachineInstr *MI) {
  if (emitPseudoExpansionLowering(*OutStreamer, MI)) {
    return;
  }

  MCInst TmpInst;
  MCInstLowering.Lower(MI, TmpInst);
  EmitToStreamer(*OutStreamer, TmpInst);
}

extern "C" LLVM_EXTERNAL_VISIBILITY void LLVMInitializeMyRISCVAsmPrinter() {
  RegisterAsmPrinter<MyRISCVAsmPrinter> X(getMyRISCV32Target());
}

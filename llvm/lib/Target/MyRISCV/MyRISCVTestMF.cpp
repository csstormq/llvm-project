#include "MyRISCV.h"
#include "llvm/CodeGen/MachineFunctionPass.h"

using namespace llvm;

namespace {

class MyRISCVTestMF : public MachineFunctionPass {
public:
  static char ID;

  MyRISCVTestMF() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override { return "MyRISCVTestMF"; }

  bool runOnMachineFunction(MachineFunction &MF) override {
    bool Changed = false;
    for (MachineBasicBlock &MBB : MF) {
      Changed |= runOnMachineBasicBlock(MBB);
    }
    return Changed;
  }

private:
  bool runOnMachineBasicBlock(MachineBasicBlock &MBB);
};

} // end anonymous namespace

char MyRISCVTestMF::ID = 0;

bool MyRISCVTestMF::runOnMachineBasicBlock(MachineBasicBlock &MBB) {
  for (MachineBasicBlock::iterator I = MBB.begin(), E = MBB.end(); I != E;
       ++I) {
    int i = 1;
  }
  return false;
}

FunctionPass *llvm::createMyRISCVTestMF() {
  return new MyRISCVTestMF();
}

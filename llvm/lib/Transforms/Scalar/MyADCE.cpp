#include "llvm/InitializePasses.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstIterator.h"

using namespace llvm;

#define DEBUG_TYPE "myadce"

namespace {

class MyADCELegacyPass : public FunctionPass {
public:
  static char ID;

  MyADCELegacyPass() : FunctionPass(ID) {
    initializeMyADCELegacyPassPass(*PassRegistry::getPassRegistry());
  }

  bool runOnFunction(Function &F) override {
    if (skipFunction(F)) {
      return false;
    }
    return removeDeadInstructions(F);
  }

  void getAnalysisUsage(AnalysisUsage& AU) const override {
    AU.setPreservesCFG();
  }

private:
  bool removeDeadInstructions(Function &F);
};

} // anonymous namespace

bool MyADCELegacyPass::removeDeadInstructions(Function &F) {
  SmallPtrSet<Instruction *, 32> Alive;
  SmallVector<Instruction *, 128> Worklist;

  for (Instruction &I : instructions(F)) {
    if (I.isDebugOrPseudoInst() || !I.isSafeToRemove()) {
      Alive.insert(&I);
      Worklist.push_back(&I);
    }
  }

  while (!Worklist.empty()) {
    Instruction *LiveInst = Worklist.pop_back_val();
    for (Use &OI : LiveInst->operands()) {
      if (Instruction *Inst = dyn_cast<Instruction>(OI)) {
        if (Alive.insert(Inst).second) {
          Worklist.push_back(Inst);
        }
      }
    }
  }

  for (Instruction &I : instructions(F)) {
    if (!Alive.count(&I)) {
      Worklist.push_back(&I);
      I.dropAllReferences();
    }
  }

  for (Instruction *&I : Worklist) {
    I->eraseFromParent();
  }

  return !Worklist.empty();
}

char MyADCELegacyPass::ID = 0;

INITIALIZE_PASS(MyADCELegacyPass, DEBUG_TYPE,
                "My Aggressive Dead Code Elimination Legacy Pass", false, false)

FunctionPass *llvm::createMyADCELegacyPass() {
  return new MyADCELegacyPass();
}

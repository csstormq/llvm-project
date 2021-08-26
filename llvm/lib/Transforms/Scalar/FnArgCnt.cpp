#include "llvm/InitializePasses.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

#define DEBUG_TYPE "fnargcnt"

namespace {

class FnArgCntLegacyPass : public FunctionPass {
public:
  static char ID;

  FnArgCntLegacyPass() : FunctionPass(ID) {
    initializeFnArgCntLegacyPassPass(*PassRegistry::getPassRegistry());
  }

  bool runOnFunction(Function &F) override {
    errs() << "FnArgCntLegacyPass --- " << F.getName()
           << ": " << F.arg_size() << "\n";
    return false;
  }
};

} // anonymous namespace

char FnArgCntLegacyPass::ID = 0;

INITIALIZE_PASS(FnArgCntLegacyPass, DEBUG_TYPE,
                "Function Argument Count Legacy Pass", false, false)

FunctionPass *llvm::createFnArgCntLegacyPass() {
  return new FnArgCntLegacyPass();
}

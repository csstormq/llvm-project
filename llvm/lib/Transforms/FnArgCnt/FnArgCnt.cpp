#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

class FnArgCntPass : public FunctionPass {
public:
  FnArgCntPass() : FunctionPass(ID) {}

  virtual bool runOnFunction(Function &F) override;

  static char ID;
};

} // anonymous namespace

char FnArgCntPass::ID = 0;

bool FnArgCntPass::runOnFunction(Function &F) {
  errs() << "FnArgCntPass --- " << F.getName() << ": " << F.arg_size() << "\n";
  return false;
}

static RegisterPass<FnArgCntPass> X(
    "plugin.fnargcnt", "Function Argument Count Pass", false, false);

#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

class FnArgCntPluginLegacyPass : public FunctionPass {
public:
  FnArgCntPluginLegacyPass() : FunctionPass(ID) {}

  bool runOnFunction(Function &F) override;

  static char ID;
};

} // anonymous namespace

char FnArgCntPluginLegacyPass::ID = 0;

bool FnArgCntPluginLegacyPass::runOnFunction(Function &F) {
  errs() << "FnArgCntPluginLegacyPass --- " << F.getName()
         << ": " << F.arg_size() << "\n";
  return false;
}

static RegisterPass<FnArgCntPluginLegacyPass> X(
    "plugin.fnargcnt", "Function Argument Count Plugin Legacy Pass",
    false, false);

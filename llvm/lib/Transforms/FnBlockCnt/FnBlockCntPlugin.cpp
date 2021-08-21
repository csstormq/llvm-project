#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/LoopInfo.h"

using namespace llvm;

namespace {

class FnBlockCntPluginLegacyPass : public FunctionPass {
public:
  FnBlockCntPluginLegacyPass() : FunctionPass(ID) {}

  bool runOnFunction(Function &F) override;

  void getAnalysisUsage(AnalysisUsage &AU) const override;

  static char ID;

private:
  void countBlocksInLoop(Loop *L, unsigned nest);
};

} // anonymous namespace

char FnBlockCntPluginLegacyPass::ID = 0;

bool FnBlockCntPluginLegacyPass::runOnFunction(Function &F) {
  errs() << "FnBlockCntPluginLegacyPass --- " << F.getName() << "\n";
  LoopInfo &LI = getAnalysis<LoopInfoWrapperPass>().getLoopInfo();
  for (Loop *L : LI) {
    countBlocksInLoop(L, 0);
  }
  return false;
}

void FnBlockCntPluginLegacyPass::countBlocksInLoop(Loop *L, unsigned Nest) {
  unsigned NumBlocks = 0;
  for(auto BB = L->block_begin(); BB != L->block_end(); ++BB) {
    NumBlocks++;
  }
  errs() << "Loop level " << Nest << " has " << NumBlocks << " blocks\n";

  std::vector<Loop *> SubLoops = L->getSubLoops();
  for (Loop::iterator I = SubLoops.begin(), E = SubLoops.end(); I != E; ++I) {
    countBlocksInLoop(*I, Nest + 1);
  }
}

void FnBlockCntPluginLegacyPass::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.addRequired<LoopInfoWrapperPass>();
}

static RegisterPass<FnBlockCntPluginLegacyPass> X(
    "plugin.fnblockcnt", "Function Block Count Plugin Legacy Pass",
    false, false);

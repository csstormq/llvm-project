#include "llvm/Transforms/FnArgCntNew/FnArgCntNew.h"

using namespace llvm;

PreservedAnalyses FnArgCntNewPass::run(Function &F,
                                       FunctionAnalysisManager &AM) {
  errs() << "FnArgCnt --- " << F.getName() << ": " << F.arg_size() << "\n";
  return PreservedAnalyses::all();
}

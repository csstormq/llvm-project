#ifndef LLVM_TRANSFORMS_FNARGCNTNEW_FNARGCNTNEW_H
#define LLVM_TRANSFORMS_FNARGCNTNEW_FNARGCNTNEW_H

#include "llvm/IR/PassManager.h"

namespace llvm {

class FnArgCntNewPass : public PassInfoMixin<FnArgCntNewPass> {
public:
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
};

} // namespace llvm

#endif // LLVM_TRANSFORMS_FNARGCNTNEW_FNARGCNTNEW_H

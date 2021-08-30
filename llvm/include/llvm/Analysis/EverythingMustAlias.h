#ifndef LLVM_ANALYSIS_EVERYTHINGMUSTALIAS_H
#define LLVM_ANALYSIS_EVERYTHINGMUSTALIAS_H

#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Pass.h"
#include <memory>

namespace llvm {

class EverythingMustAliasResult : public AAResultBase<EverythingMustAliasResult> {
public:
  AliasResult alias(const MemoryLocation &LocA, const MemoryLocation &LocB,
                    AAQueryInfo &AAQI);
};

class EverythingMustAliasLegacyPass : public ImmutablePass {
public:
  static char ID;

  EverythingMustAliasLegacyPass();

  bool doInitialization(Module &M) override;

  EverythingMustAliasResult &getResult() { return *Result; }
  const EverythingMustAliasResult &getResult() const { return *Result; }

private:
  std::unique_ptr<EverythingMustAliasResult> Result;
};

} // end namespace llvm

#endif // LLVM_ANALYSIS_EVERYTHINGMUSTALIAS_H

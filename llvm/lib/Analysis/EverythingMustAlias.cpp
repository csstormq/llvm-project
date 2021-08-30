#include "llvm/Analysis/EverythingMustAlias.h"
#include "llvm/Analysis/Analysis.h"
#include "llvm/InitializePasses.h"

using namespace llvm;

#define DEBUG_TYPE "must-aa"

AliasResult EverythingMustAliasResult::alias(const MemoryLocation &LocA,
                                             const MemoryLocation &LocB,
                                             AAQueryInfo &AAQI) {
  return AliasResult::MustAlias;
}

EverythingMustAliasLegacyPass::EverythingMustAliasLegacyPass()
    : ImmutablePass(ID) {
  initializeEverythingMustAliasLegacyPassPass(*PassRegistry::getPassRegistry());
}

bool EverythingMustAliasLegacyPass::doInitialization(Module &M) {
  Result.reset(new EverythingMustAliasResult());
  return false;
}

char EverythingMustAliasLegacyPass::ID = 0;

INITIALIZE_PASS(EverythingMustAliasLegacyPass, DEBUG_TYPE,
                "Everything Alias (always returns 'must' alias)", true, true)

ImmutablePass *llvm::createEverythingMustAliasLegacyPass() {
  return new EverythingMustAliasLegacyPass();
}

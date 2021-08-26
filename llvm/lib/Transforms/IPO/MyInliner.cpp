#include "llvm/InitializePasses.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/IPO/Inliner.h"
#include "llvm/Analysis/InlineCost.h"

using namespace llvm;

#define DEBUG_TYPE "myinliner"

namespace {

class MyInlinerLegacyPass : public LegacyInlinerBase {
public:
  static char ID;

  MyInlinerLegacyPass() : LegacyInlinerBase(ID) {
    initializeMyInlinerLegacyPassPass(*PassRegistry::getPassRegistry());
  }

  InlineCost getInlineCost(CallBase &CB) override;
};

} // anonymous namespace

InlineCost MyInlinerLegacyPass::getInlineCost(CallBase &CB) {
  if (!CB.hasFnAttr(Attribute::AlwaysInline)) {
    return InlineCost::getNever("no alwaysinline attribute");
  }

  Function *Callee = CB.getCalledFunction();

  if (!Callee) {
    return InlineCost::getNever("indirect function invocation");
  }

  if (Callee->isDeclaration()) {
    return InlineCost::getNever("no function definition");
  }

  if (Callee->isPresplitCoroutine()) {
    return InlineCost::getNever("unsplited coroutine call");
  }

  auto IsVisble = isInlineViable(*Callee);
  if (!IsVisble.isSuccess()) {
    return InlineCost::getNever(IsVisble.getFailureReason());
  }

  return InlineCost::getAlways("always inliner");
}

char MyInlinerLegacyPass::ID = 0;

INITIALIZE_PASS(MyInlinerLegacyPass, DEBUG_TYPE,
                "Inliner for always_inline functions Legacy Pass", false, false)

Pass *llvm::createMyInlinerLegacyPass() {
  return new MyInlinerLegacyPass();
}

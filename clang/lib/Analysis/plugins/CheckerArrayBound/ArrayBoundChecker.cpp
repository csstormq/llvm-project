#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/DynamicExtent.h"

using namespace clang;
using namespace ento;

namespace {

class ArrayBoundChecker : public Checker<check::Location> {
  mutable std::unique_ptr<BugType> OutOfBoundBT;

  void checkOutOfBound(const ElementRegion *ER, CheckerContext &C) const;

  void reportOutOfBound(CheckerContext &C) const;

public:
  void checkLocation(const SVal &Location, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;
};

} // anonymous namespace

void ArrayBoundChecker::checkLocation(const SVal &Location, bool IsLoad,
                                      const Stmt *S, CheckerContext &C) const {
  const MemRegion *MR = Location.getAsRegion();
  if (!MR) {
    return;
  }

  llvm::SmallPtrSet<const MemRegion *, 32> SuperRegions;

  SuperRegions.insert(MR);
  while (const SubRegion *SubR = MR->getAs<SubRegion>()) {
    MR = SubR->getSuperRegion();
    SuperRegions.insert(MR);
  }

  for (const auto MR : SuperRegions) {
    const ElementRegion *ER = MR->getAs<ElementRegion>();
    if (ER && !ER->getIndex().isZeroConstant()) {
      checkOutOfBound(ER, C);
    }
  }
}

void ArrayBoundChecker::checkOutOfBound(const ElementRegion *ER,
                                        CheckerContext &C) const {
  assert(ER);

  Optional<NonLoc> NV = ER->getIndex().getAs<NonLoc>();
  if (!NV) {
    return;
  }

  ProgramStateRef State = C.getState();

  DefinedOrUnknownSVal ElementCount = getDynamicElementCount(State,
    ER->getSuperRegion(), C.getSValBuilder(), ER->getValueType());
  Optional<nonloc::ConcreteInt> CV = ElementCount.getAs<nonloc::ConcreteInt>();
  if (!CV) {
    return;
  }

  llvm::APSInt Upper = llvm::APSInt::get(CV->getValue().getLimitedValue() - 1);
  llvm::APSInt Zero(Upper.getBitWidth(), Upper.isUnsigned());

  ProgramStateRef StateInBound, StateOutOfBound;
  std::tie(StateInBound, StateOutOfBound) =
    C.getConstraintManager().assumeInclusiveRangeDual(State, *NV, Zero, Upper);
  const bool IsOutOfBound = StateOutOfBound && !StateInBound;

  if (IsOutOfBound) {
    reportOutOfBound(C);
  }
  else {
    C.addTransition(StateInBound);
  }
}

void ArrayBoundChecker::reportOutOfBound(CheckerContext &C) const {
  if (!OutOfBoundBT) {
    OutOfBoundBT.reset(new BugType(this, "Out of bound memory access",
      "Access out-of-bound array element (buffer overflow)"));
  }

  if (ExplodedNode *N = C.generateErrorNode()) {
    auto R = std::make_unique<PathSensitiveBugReport>(
      *OutOfBoundBT, OutOfBoundBT->getDescription(), N);
    C.emitReport(std::move(R));
  }
}

// Register plugin!
extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<ArrayBoundChecker>("plugin.alpha.security.ArrayBound",
    "Warn about buffer overflows.", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
  CLANG_ANALYZER_API_VERSION_STRING;

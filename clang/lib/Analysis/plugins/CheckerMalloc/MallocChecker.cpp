#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"

using namespace clang;
using namespace ento;

namespace {

typedef SmallVector<SymbolRef, 2> SymbolVector;

enum Kind {
  Allocated,
  Released,
};

class MallocChecker : public Checker<check::PostCall, eval::Assume,
                                     check::DeadSymbols, check::PointerEscape> {
  mutable std::unique_ptr<BugType> DoubleFreeBT;
  mutable std::unique_ptr<BugType> LeakBT;

  CallDescription MallocFn;
  CallDescription FreeFn;
  CallDescription ReallocFn;

  void checkMalloc(const CallEvent &Call, CheckerContext &C) const;
  void checkFree(const CallEvent &Call, CheckerContext &C) const;
  void checkRealloc(const CallEvent &Call, CheckerContext &C) const;

  ProgramStateRef MallocMemAux(const CallEvent &Call, CheckerContext &C,
                               ProgramStateRef State) const;
  ProgramStateRef FreeMemAux(const CallEvent &Call, CheckerContext &C,
                             ProgramStateRef State) const;
  ProgramStateRef ReallocMemAux(const CallEvent &Call, CheckerContext &C,
                                ProgramStateRef State) const;

  void reportDoubleFree(CheckerContext &C) const;
  void reportLeaks(ArrayRef<SymbolRef> LeakedStreams, CheckerContext &C,
                   ProgramStateRef State) const;

  using LeakInfo = std::pair<const ExplodedNode *, const MemRegion *>;
  static LeakInfo getAllocationSite(const ExplodedNode *N, SymbolRef Sym,
                                    CheckerContext &C);

public:
  MallocChecker() : MallocFn("malloc"), FreeFn("free"), ReallocFn("realloc") {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  ProgramStateRef evalAssume(ProgramStateRef State, const SVal &Cond,
                             bool Assumption) const;
  void checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const;
  ProgramStateRef checkPointerEscape(ProgramStateRef State,
                                     const InvalidatedSymbols &Escaped,
                                     const CallEvent *Call,
                                     PointerEscapeKind Kind) const;
};

} // anonymous namespace

REGISTER_MAP_WITH_PROGRAMSTATE(RegionState, SymbolRef, int)
REGISTER_MAP_WITH_PROGRAMSTATE(ReallocPairs, SymbolRef, SymbolRef)

void MallocChecker::checkPostCall(const CallEvent &Call,
                                  CheckerContext &C) const {
  if (!Call.isGlobalCFunction()) {
    return;
  }

  if (Call.isCalled(MallocFn)) {
    checkMalloc(Call, C);
    return;
  }

  if (Call.isCalled(FreeFn)) {
    checkFree(Call, C);
    return;
  }

  if (Call.isCalled(ReallocFn)) {
    checkRealloc(Call, C);
    return;
  }
}

void MallocChecker::checkMalloc(const CallEvent &Call,
                                CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  State = MallocMemAux(Call, C, State);
  C.addTransition(State);
}

ProgramStateRef
MallocChecker::MallocMemAux(const CallEvent &Call, CheckerContext &C,
                            ProgramStateRef State) const {
  if (!State) {
    return nullptr;
  }

  SymbolRef Sym = Call.getReturnValue().getAsSymbol();
  if (!Sym) {
    return nullptr;
  }

  return State->set<RegionState>(Sym, Allocated);
}

void MallocChecker::checkFree(const CallEvent &Call,
                              CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  State = FreeMemAux(Call, C, State);
  C.addTransition(State);
}

ProgramStateRef
MallocChecker::FreeMemAux(const CallEvent &Call, CheckerContext &C,
                          ProgramStateRef State) const {
  if (!State) {
    return nullptr;
  }

  SymbolRef Sym = Call.getArgSVal(0).getAsSymbol();
  if (!Sym) {
    return nullptr;
  }

  const auto K = State->get<RegionState>(Sym);
  if (!K || *K == Allocated) {
    return State->set<RegionState>(Sym, Released);
  }
  if (*K == Released) {
    reportDoubleFree(C);
  }

  return nullptr;
}

void MallocChecker::checkRealloc(const CallEvent &Call,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  State = ReallocMemAux(Call, C, State);
  C.addTransition(State);
}

ProgramStateRef
MallocChecker::ReallocMemAux(const CallEvent &Call, CheckerContext &C,
                             ProgramStateRef State) const {
  if (!State) {
    return nullptr;
  }

  Optional<DefinedSVal> Arg0 = Call.getArgSVal(0).getAs<DefinedSVal>();
  Optional<DefinedSVal> Arg1 = Call.getArgSVal(1).getAs<DefinedSVal>();
  if (!Arg0 || !Arg1) {
    return nullptr;
  }

  ConstraintManager &CM = C.getConstraintManager();
  ProgramStateRef StatePtrNotNull, StatePtrIsNull;
  std::tie(StatePtrNotNull, StatePtrIsNull) = CM.assumeDual(State, *Arg0);
  ProgramStateRef StateSizeNotZero, StateSizeIsZero;
  std::tie(StateSizeNotZero, StateSizeIsZero) = CM.assumeDual(State, *Arg1);
  const bool PtrIsNull = StatePtrIsNull && !StatePtrNotNull;
  const bool SizeIsZero = StateSizeIsZero && !StateSizeNotZero;

  if (PtrIsNull) {
    ProgramStateRef StateMalloc = MallocMemAux(Call, C, StatePtrIsNull);
    return StateMalloc;
  }

  if (!PtrIsNull && SizeIsZero) {
    ProgramStateRef StateFree = FreeMemAux(Call, C, StateSizeIsZero);
    return StateFree;
  }

  if (ProgramStateRef StateFree = FreeMemAux(Call, C, State)) {
    ProgramStateRef StateRealloc = MallocMemAux(Call, C, StateFree);
    if (!StateRealloc) {
      return nullptr;
    }

    SymbolRef FromPtr = Call.getArgSVal(0).getAsSymbol();
    SymbolRef ToPtr = Call.getReturnValue().getAsSymbol();
    assert(FromPtr && ToPtr &&
           "By this point, FreeMemAux and MallocMemAux should have checked "
           "whether the argument or the return value is symbolic!");
    return StateRealloc->set<ReallocPairs>(ToPtr, FromPtr);
  }

  return nullptr;
}

void MallocChecker::reportDoubleFree(CheckerContext &C) const {
  if (!DoubleFreeBT) {
    DoubleFreeBT.reset(new BugType(this, "Double free", "Memory Error"));
  }

  if (ExplodedNode *N = C.generateErrorNode()) {
    auto R = std::make_unique<PathSensitiveBugReport>(
      *DoubleFreeBT, DoubleFreeBT->getDescription(), N);
    C.emitReport(std::move(R));
  }
}

ProgramStateRef MallocChecker::evalAssume(ProgramStateRef State,
                                          const SVal &Cond,
                                          bool Assumption) const {
  auto isNull = [&](ProgramStateRef State, SymbolRef Sym) {
    // Return true if a symbol is NULL.
    return State->getConstraintManager().isNull(State, Sym).isConstrainedTrue();
  };

  for (const auto &TrackedRegion : State->get<RegionState>()) {
    SymbolRef R = TrackedRegion.first;
    if (isNull(State, R)) {
      State = State->remove<RegionState>(R);
    }
  }

  for (const auto &ReallocPair : State->get<ReallocPairs>()) {
    SymbolRef ToPtr = ReallocPair.first;
    if (isNull(State, ToPtr)) {
      State = State->remove<ReallocPairs>(ToPtr);
      SymbolRef FromPtr = ReallocPair.second;
      State = State->set<RegionState>(FromPtr, Allocated);
    }
  }

  return State;
}

void MallocChecker::checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const {
  auto isNotNull = [&](ProgramStateRef State, SymbolRef Sym) {
    // Return true if a symbol is not NULL.
    return !State->getConstraintManager().isNull(State, Sym).isConstrainedTrue();
  };

  ProgramStateRef State = C.getState();
  SymbolVector LeakedSyms, DeadSyms;
  for (const auto &TrackedRegion : State->get<RegionState>()) {
    SymbolRef Sym = TrackedRegion.first;
    if (SR.isLive(Sym)) {
      continue;
    }
    DeadSyms.push_back(Sym);

    if (TrackedRegion.second == Allocated && isNotNull(State, Sym)) {
      LeakedSyms.push_back(Sym);
    }
  }

  if (DeadSyms.empty()) {
    return;
  }

  for (const auto &ReallocPair : State->get<ReallocPairs>()) {
    if (SR.isDead(ReallocPair.first) || SR.isDead(ReallocPair.second)) {
      State = State->remove<ReallocPairs>(ReallocPair.first);
    }
  }

  if (!LeakedSyms.empty()) {
    reportLeaks(LeakedSyms, C, State);
  }

  for (const auto &DeadSym : DeadSyms) {
    State = State->remove<RegionState>(DeadSym);
  }

  C.addTransition(State);
}

MallocChecker::LeakInfo
MallocChecker::getAllocationSite(const ExplodedNode *N, SymbolRef Sym,
                                 CheckerContext &C) {
  const LocationContext *LeakContext = N->getLocationContext();
  const ExplodedNode *AllocNode = N;
  const MemRegion *ReferenceRegion = nullptr;

  while (N) {
    ProgramStateRef State = N->getState();
    if (!State->get<RegionState>(Sym)) {
      break;
    }

    if (!ReferenceRegion) {
      if (const MemRegion *MR = C.getLocationRegionIfPostStore(N)) {
        SVal Val = State->getSVal(MR);
        if (Val.getAsLocSymbol() == Sym) {
          const VarRegion *VR = MR->getBaseRegion()->getAs<VarRegion>();
          if (!VR || (VR->getStackFrame() == LeakContext->getStackFrame())) {
            ReferenceRegion = MR;
          }
        }
      }
    }

    const LocationContext *NContext = N->getLocationContext();
    if (NContext == LeakContext || NContext->isParentOf(LeakContext)) {
      AllocNode = N;
    }
    N = N->pred_empty() ? nullptr : *(N->pred_begin());
  }

  return LeakInfo(AllocNode, ReferenceRegion);
}

void MallocChecker::reportLeaks(ArrayRef<SymbolRef> LeakedSyms,
                                CheckerContext &C,
                                ProgramStateRef State) const {
  ExplodedNode *N = C.generateNonFatalErrorNode(State);
  if (!N) {
    return;
  }

  if (!LeakBT) {
    LeakBT.reset(new BugType(this, "Memory Leak", "Memory Error",
      /*SuppressOnSink=*/true));
  }

  for (const auto &LeakedMem : LeakedSyms) {
    PathDiagnosticLocation LocUsedForUniqueing;
    const ExplodedNode *AllocNode = nullptr;
    const MemRegion *Region = nullptr;
    std::tie(AllocNode, Region) = getAllocationSite(N, LeakedMem, C);

    const Stmt *AllocationStmt = AllocNode->getStmtForDiagnostics();
    if (AllocationStmt) {
      LocUsedForUniqueing = PathDiagnosticLocation::createBegin(AllocationStmt,
        C.getSourceManager(), AllocNode->getLocationContext());
    }

    SmallString<200> buf;
    llvm::raw_svector_ostream os(buf);
    if (Region && Region->canPrintPretty()) {
      os << "Potential leak of memory pointed to by ";
      Region->printPretty(os);
      os << " located at ";
      LocUsedForUniqueing.asLocation().print(os, C.getSourceManager());
    }
    else {
      os << "Potential memory leak";
    }

    auto R = std::make_unique<PathSensitiveBugReport>(*LeakBT, os.str(), N,
      LocUsedForUniqueing, AllocNode->getLocationContext()->getDecl());
    C.emitReport(std::move(R));
  }
}

ProgramStateRef
MallocChecker::checkPointerEscape(ProgramStateRef State,
                                  const InvalidatedSymbols &Escaped,
                                  const CallEvent *Call,
                                  PointerEscapeKind Kind) const {
  if (Kind == PSK_DirectEscapeOnCall && Call->isInSystemHeader()) {
    return State;
  }

  for (SymbolRef Sym : Escaped) {
    State = State->remove<RegionState>(Sym);
    State = State->remove<ReallocPairs>(Sym);
  }
  return State;
}

// Register plugin!
extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<MallocChecker>("plugin.unix.Malloc",
    "Check for memory leaks, double free, and use-after-free problems.", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
  CLANG_ANALYZER_API_VERSION_STRING;

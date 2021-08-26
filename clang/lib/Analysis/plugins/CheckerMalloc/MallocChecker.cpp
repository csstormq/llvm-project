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
                                     check::DeadSymbols, check::PointerEscape,
                                     check::Location, check::PreCall,
                                     check::EndFunction> {
  mutable std::unique_ptr<BugType> DoubleFreeBT;
  mutable std::unique_ptr<BugType> LeakBT;
  mutable std::unique_ptr<BugType> UseAfterFreeBT;

  CallDescription FunOpenFn;

  void checkMalloc(const CallEvent &Call, CheckerContext &C) const;
  void checkFree(const CallEvent &Call, CheckerContext &C) const;
  void checkRealloc(const CallEvent &Call, CheckerContext &C) const;
  void checkCalloc(const CallEvent &Call, CheckerContext &C) const;
  void checkUseAfterFree(SymbolRef Sym, CheckerContext &C,
                         const char *Msg = nullptr) const;

  ProgramStateRef MallocMemAux(const CallEvent &Call, CheckerContext &C,
                               ProgramStateRef State,
                               Optional<SVal> Init = None) const;
  ProgramStateRef FreeMemAux(const CallEvent &Call, CheckerContext &C,
                             ProgramStateRef State,
                             bool *IsKnownToBeAllocated = nullptr) const;
  ProgramStateRef ReallocMemAux(const CallEvent &Call, CheckerContext &C,
                                ProgramStateRef State) const;

  void reportDoubleFree(CheckerContext &C) const;
  void reportLeaks(ArrayRef<SymbolRef> LeakedStreams, CheckerContext &C,
                   ExplodedNode *N) const;
  void reportUseAfterFree(CheckerContext &C, const char *Msg = nullptr) const;

  using LeakInfo = std::pair<const ExplodedNode *, const MemRegion *>;
  static LeakInfo getAllocationSite(const ExplodedNode *N, SymbolRef Sym,
                                    CheckerContext &C);

  bool mayFreeAnyEscapedMemoryOrIsModeledExplicitly(const CallEvent *Call) const;
  bool isMemCall(const CallEvent &Call) const;
  bool isFreeingMemCall(const CallEvent &Call) const;

  using CheckFn = std::function<void(const MallocChecker *,
                                     const CallEvent &Call, CheckerContext &C)>;

  const CallDescriptionMap<CheckFn> FreeingMemFnMap{
    {{"free", 1}, &MallocChecker::checkFree},
  };

  const CallDescriptionMap<CheckFn> AllocatingMemFnMap{
    {{"malloc", 1}, &MallocChecker::checkMalloc},
    {{"valloc", 1}, &MallocChecker::checkMalloc},
    {{"calloc", 2}, &MallocChecker::checkCalloc},
  };

  const CallDescriptionMap<CheckFn> ReallocatingMemFnMap{
    {{"realloc", 2}, &MallocChecker::checkRealloc},
  };

public:
  MallocChecker() : FunOpenFn("funopen") {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  ProgramStateRef evalAssume(ProgramStateRef State, const SVal &Cond,
                             bool Assumption) const;
  void checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const;
  ProgramStateRef checkPointerEscape(ProgramStateRef State,
                                     const InvalidatedSymbols &Escaped,
                                     const CallEvent *Call,
                                     PointerEscapeKind Kind) const;
  void checkLocation(const SVal &Location, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
};

struct ReallocPair {
  enum OwnershipAfterReallocKind {
    OAR_NeedToFreeAfterFailure,
    OAR_DoNotTrackAfterFailure,
  };

  SymbolRef RealloctedSym;
  OwnershipAfterReallocKind Kind;

  ReallocPair(SymbolRef FromPtr, OwnershipAfterReallocKind K)
    : RealloctedSym(FromPtr), Kind(K) {}

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddPointer(RealloctedSym);
    ID.AddInteger(Kind);
  }

  bool operator==(const ReallocPair &Other) const {
    return RealloctedSym == Other.RealloctedSym && Kind == Other.Kind;
  }
};

} // anonymous namespace

REGISTER_MAP_WITH_PROGRAMSTATE(RegionState, SymbolRef, int)
REGISTER_MAP_WITH_PROGRAMSTATE(ReallocPairs, SymbolRef, ReallocPair)

void MallocChecker::checkPostCall(const CallEvent &Call,
                                  CheckerContext &C) const {
  if (!Call.isGlobalCFunction()) {
    return;
  }

  if (const CheckFn *Callback = FreeingMemFnMap.lookup(Call)) {
    (*Callback)(this, Call, C);
    return;
  }

  if (const CheckFn *Callback = AllocatingMemFnMap.lookup(Call)) {
    (*Callback)(this, Call, C);
    return;
  }

  if (const CheckFn *Callback = ReallocatingMemFnMap.lookup(Call)) {
    (*Callback)(this, Call, C);
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
                            ProgramStateRef State,
                            Optional<SVal> Init /*= None*/) const {
  if (!State) {
    return nullptr;
  }

  SymbolRef Sym = Call.getReturnValue().getAsSymbol();
  if (!Sym) {
    return nullptr;
  }

  const Expr *CE = Call.getOriginExpr();
  const unsigned Count = C.blockCount();
  SValBuilder &SVB = C.getSValBuilder();
  const LocationContext *LCtx = C.getPredecessor()->getLocationContext();
  if (Optional<DefinedSVal> DV =
      SVB.getConjuredHeapSymbolVal(CE, LCtx, Count).getAs<DefinedSVal>()) {
    State = State->BindExpr(CE, C.getLocationContext(), *DV);
    if (Init) {
      State = State->bindDefaultInitial(*DV, *Init, LCtx);
    }
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
                          ProgramStateRef State,
                          bool *IsKnownToBeAllocated /*= nullptr*/) const {
  if (!State) {
    return nullptr;
  }

  SymbolRef Sym = Call.getArgSVal(0).getAsSymbol(true);
  if (!Sym) {
    return nullptr;
  }

  const auto K = State->get<RegionState>(Sym);
  if (!K) {
    return State->set<RegionState>(Sym, Released);
  }
  if (*K == Allocated) {
    if (IsKnownToBeAllocated) {
      *IsKnownToBeAllocated = true;
    }
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

  bool IsKnownToBeAllocated = false;
  if (ProgramStateRef StateFree
      = FreeMemAux(Call, C, State, &IsKnownToBeAllocated)) {
    ProgramStateRef StateRealloc = MallocMemAux(Call, C, StateFree);
    if (!StateRealloc) {
      return nullptr;
    }

    SymbolRef FromPtr = Call.getArgSVal(0).getAsSymbol(true);
    SymbolRef ToPtr = Call.getReturnValue().getAsSymbol();
    assert(FromPtr && ToPtr &&
           "By this point, FreeMemAux and MallocMemAux should have checked "
           "whether the argument or the return value is symbolic!");
    return StateRealloc->set<ReallocPairs>(ToPtr, ReallocPair(FromPtr,
      IsKnownToBeAllocated ? ReallocPair::OAR_NeedToFreeAfterFailure
                           : ReallocPair::OAR_DoNotTrackAfterFailure));
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

void MallocChecker::checkCalloc(const CallEvent &Call,
                                CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  SValBuilder &SVB = C.getSValBuilder();
  SVal ZeroVal = SVB.makeZeroVal(SVB.getContext().CharTy);
  State = MallocMemAux(Call, C, State, ZeroVal);
  C.addTransition(State);
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
      SymbolRef FromPtr = ReallocPair.second.RealloctedSym;
      switch (ReallocPair.second.Kind) {
        case ReallocPair::OAR_NeedToFreeAfterFailure:
          State = State->set<RegionState>(FromPtr, Allocated);
          break;
        case ReallocPair::OAR_DoNotTrackAfterFailure:
          State = State->remove<RegionState>(FromPtr);
          break;
        default:
          llvm_unreachable("Unkonwn OwnershipAfterReallocKind.");
      }
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

  SymbolVector LeakedSyms;
  for (const auto &TrackedRegion : State->get<RegionState>()) {
    SymbolRef Sym = TrackedRegion.first;
    if (SR.isDead(Sym)) {
      if (TrackedRegion.second == Allocated && isNotNull(State, Sym)) {
        LeakedSyms.push_back(Sym);
      }
      State = State->remove<RegionState>(Sym);
    }
  }

  for (const auto &ReallocPair : State->get<ReallocPairs>()) {
    if (SR.isDead(ReallocPair.first)) {
      State = State->remove<ReallocPairs>(ReallocPair.first);
    }
  }

  if (LeakedSyms.empty()) {
    return;
  }

  if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
    reportLeaks(LeakedSyms, C, N);
    C.addTransition(State, N);
  }
}

void MallocChecker::reportLeaks(ArrayRef<SymbolRef> LeakedSyms,
                                CheckerContext &C,
                                ExplodedNode *N) const {
  assert(N);

  if (!LeakBT) {
    LeakBT.reset(new BugType(this, "Memory Leak", "Memory Error",
      /*SuppressOnSink=*/true));
  }

  for (const auto &LeakedSym : LeakedSyms) {
    PathDiagnosticLocation LocUsedForUniqueing;
    const ExplodedNode *AllocNode = nullptr;
    const MemRegion *Region = nullptr;
    std::tie(AllocNode, Region) = getAllocationSite(N, LeakedSym, C);

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

ProgramStateRef
MallocChecker::checkPointerEscape(ProgramStateRef State,
                                  const InvalidatedSymbols &Escaped,
                                  const CallEvent *Call,
                                  PointerEscapeKind Kind) const {
  if (Kind == PSK_DirectEscapeOnCall && 
      !mayFreeAnyEscapedMemoryOrIsModeledExplicitly(Call)) {
    return State;
  }

  for (SymbolRef Sym : Escaped) {
    State = State->remove<RegionState>(Sym);
    State = State->remove<ReallocPairs>(Sym);
  }
  return State;
}

bool MallocChecker::mayFreeAnyEscapedMemoryOrIsModeledExplicitly(
                                              const CallEvent *Call) const {
  assert(Call);

  if (isMemCall(*Call)) {
    return false;
  }

  if (!Call->isInSystemHeader()) {
    return true;
  }

  if (Call->isCalled(FunOpenFn)) {
    if (Call->getNumArgs() >= 4 && Call->getArgSVal(4).isConstant(0)) {
      return false;
    }
  }

  if (Call->argumentsMayEscape()) {
    return true;
  }

  return false;
}

bool MallocChecker::isMemCall(const CallEvent &Call) const {
  if (!Call.isGlobalCFunction()) {
    return false;
  }
  return isFreeingMemCall(Call) || AllocatingMemFnMap.lookup(Call);
}

void MallocChecker::checkLocation(const SVal &Location, bool IsLoad,
                                  const Stmt *S, CheckerContext &C) const {
  SymbolRef Sym = Location.getAsSymbol(true);
  if (Sym) {
    checkUseAfterFree(Sym, C);
  }
}

void MallocChecker::checkUseAfterFree(SymbolRef Sym, CheckerContext &C,
                                      const char *Msg /*= nullptr*/) const {
  assert(Sym);
  const auto K = C.getState()->get<RegionState>(Sym);
  if (K && *K == Released) {
    reportUseAfterFree(C, Msg);
  }
}

void MallocChecker::reportUseAfterFree(CheckerContext &C,
                                       const char *Msg /*= nullptr*/) const {
  if (!UseAfterFreeBT) {
    UseAfterFreeBT.reset(new BugType(this, "Use of memory after it is freed",
      "Memory Error"));
  }

  if (ExplodedNode *N = C.generateErrorNode()) {
    auto R = std::make_unique<PathSensitiveBugReport>(
      *UseAfterFreeBT, Msg ? Msg : UseAfterFreeBT->getDescription(), N);
    C.emitReport(std::move(R));
  }
}

void MallocChecker::checkPreCall(const CallEvent &Call,
                                 CheckerContext &C) const {
  if (isFreeingMemCall(Call)) {
    return;
  }

  for (unsigned I = 0, E = Call.getNumArgs(); I < E; ++I) {
    SymbolRef Sym = Call.getArgSVal(I).getAsSymbol(true);
    if (Sym) {
      checkUseAfterFree(Sym, C, "Potential use of memory after it is freed");
    }
  }
}

bool MallocChecker::isFreeingMemCall(const CallEvent &Call) const {
  if (!Call.isGlobalCFunction()) {
    return false;
  }
  return FreeingMemFnMap.lookup(Call) || ReallocatingMemFnMap.lookup(Call);
}

void MallocChecker::checkEndFunction(const ReturnStmt *RS,
                                     CheckerContext &C) const {
  if (!RS) {
    return;
  }

  if (const Expr *E = RS->getRetValue()) {
    SymbolRef Sym = C.getSVal(E).getAsSymbol(true);
    if (Sym) {
      checkUseAfterFree(Sym, C, "Potential use of memory after it is freed");
    }
  }
}

// Register plugin!
extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<MallocChecker>("plugin.unix.Malloc",
    "Check for memory leaks, double free, and use-after-free problems.", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
  CLANG_ANALYZER_API_VERSION_STRING;

#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"

using namespace clang;
using namespace ento;

namespace {

enum Kind {
  Opened,
  Closed,
};

class SimpleStreamChecker : public Checker<check::PostCall,
                                           check::DeadSymbols> {
  mutable std::unique_ptr<BugType> DoubleCloseBT;
  CallDescription OpenFn;
  CallDescription CloseFn;

  void reportDoubleClose(CheckerContext &C) const;

public:
  SimpleStreamChecker() : OpenFn("fopen"), CloseFn("fclose") {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  void checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const;
};

} // anonymous namespace

REGISTER_MAP_WITH_PROGRAMSTATE(SimpleStreamMap, SymbolRef, int)

void SimpleStreamChecker::checkPostCall(const CallEvent &Call,
                                        CheckerContext &C) const {
  if (!Call.isGlobalCFunction()) {
    return;
  }

  if (Call.isCalled(OpenFn)) {
    SymbolRef FileDesc = Call.getReturnValue().getAsSymbol();
    if (!FileDesc) {
      return;
    }

    ProgramStateRef State = C.getState();
    State = State->set<SimpleStreamMap>(FileDesc, Opened);
    C.addTransition(State);
    return;
  }

  if (Call.isCalled(CloseFn)) {
    SymbolRef FileDesc = Call.getArgSVal(0).getAsSymbol();
    if (!FileDesc) {
      return;
    }

    ProgramStateRef State = C.getState();
    if (const auto K = State->get<SimpleStreamMap>(FileDesc)) {
      if (*K == Opened) {
        State = State->set<SimpleStreamMap>(FileDesc, Closed);
        C.addTransition(State);
      }
      else if (*K == Closed) {
        reportDoubleClose(C);
      }
    }
    return;
  }
}

void SimpleStreamChecker::reportDoubleClose(CheckerContext &C) const {
  if (!DoubleCloseBT) {
    DoubleCloseBT.reset(
      new BugType(this, "Double fclose", "Unix Stream API Error"));
  }

  if (ExplodedNode *N = C.generateErrorNode()) {
    auto R = std::make_unique<PathSensitiveBugReport>(
      *DoubleCloseBT, DoubleCloseBT->getDescription(), N);
    C.emitReport(std::move(R));
  }
}

void SimpleStreamChecker::checkDeadSymbols(SymbolReaper &SR,
                                           CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  for (const auto &TrackedStream : State->get<SimpleStreamMap>()) {
    SymbolRef Sym = TrackedStream.first;
    if (SR.isDead(Sym)) {
      State = State->remove<SimpleStreamMap>(Sym);
    }
  }

  C.addTransition(State);
}

// Register plugin!
extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SimpleStreamChecker>(
    "plugin.alpha.unix.SimpleStream", "Check for misuses of stream APIs", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
  CLANG_ANALYZER_API_VERSION_STRING;

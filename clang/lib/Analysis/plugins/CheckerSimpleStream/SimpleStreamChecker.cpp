#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"

using namespace clang;
using namespace ento;

namespace {

// Kind of stream API status
enum Kind {
  Opened,
  Closed,
};

class SimpleStreamChecker : public Checker<check::PostCall> {
  mutable std::unique_ptr<BugType> DoubleCloseBT;

  void reportDoubleClose(CheckerContext &C) const;

public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
};

} // anonymous namespace

REGISTER_MAP_WITH_PROGRAMSTATE(SimpleStreamMap, SymbolRef, int)

void SimpleStreamChecker::checkPostCall(const CallEvent &Call,
                                        CheckerContext &C) const {
  if (!Call.isGlobalCFunction()) {
    return;
  }

  const IdentifierInfo *II = Call.getCalleeIdentifier();
  if (!II) {
    return;
  }

  if (II->isStr("fopen")) {
    SymbolRef FileDesc = Call.getReturnValue().getAsSymbol();
    if (!FileDesc) {
      return;
    }

    ProgramStateRef State = C.getState();
    State = State->set<SimpleStreamMap>(FileDesc, Opened);
    C.addTransition(State);
  }
  else if (II->isStr("fclose")) {
    SymbolRef FileDesc = Call.getArgSVal(0).getAsSymbol();
    if (!FileDesc) {
      return;
    }

    ProgramStateRef State = C.getState();
    const auto Status = State->get<SimpleStreamMap>(FileDesc);
    if (!Status) {
      return;
    }
    if (*Status == Opened) {
      State = State->set<SimpleStreamMap>(FileDesc, Closed);
      C.addTransition(State);
    }
    else if (*Status == Closed) {
      reportDoubleClose(C);
    }
  }
}

void SimpleStreamChecker::reportDoubleClose(CheckerContext &C) const {
  if (!DoubleCloseBT) {
    DoubleCloseBT.reset(
      new BugType(this, "Double fclose","Unix Stream API Error"));
  }
  ExplodedNode *N = C.generateErrorNode();
  auto R = std::make_unique<PathSensitiveBugReport>(
    *DoubleCloseBT, DoubleCloseBT->getDescription(), N);
  C.emitReport(std::move(R));
}

// Register plugin!
extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SimpleStreamChecker>(
    "plugin.alpha.unix.SimpleStream", "Check for misuses of stream APIs", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
  CLANG_ANALYZER_API_VERSION_STRING;

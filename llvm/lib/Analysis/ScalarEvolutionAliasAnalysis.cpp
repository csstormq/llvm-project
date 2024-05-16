//===- ScalarEvolutionAliasAnalysis.cpp - SCEV-based Alias Analysis -------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file defines the ScalarEvolutionAliasAnalysis pass, which implements a
// simple alias analysis implemented in terms of ScalarEvolution queries.
//
// This differs from traditional loop dependence analysis in that it tests
// for dependencies within a single iteration of a loop, rather than
// dependencies between different iterations.
//
// ScalarEvolution has a more complete understanding of pointer arithmetic
// than BasicAliasAnalysis' collection of ad-hoc analyses.
//
//===----------------------------------------------------------------------===//

#include "llvm/Analysis/ScalarEvolutionAliasAnalysis.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionExpressions.h"
#include "llvm/InitializePasses.h"
using namespace llvm;

static bool canComputePointerDiff(ScalarEvolution &SE,
                                  const SCEV *A, const SCEV *B) {
  if (SE.getEffectiveSCEVType(A->getType()) !=
      SE.getEffectiveSCEVType(B->getType()))
    return false;

  return SE.instructionCouldExistWithOperands(A, B);
}

static bool areMemAccessesDisjoint(ScalarEvolution &SE, const SCEV *AS,
                                   uint64_t WidthA, const SCEV *BS,
                                   uint64_t WidthB) {
  uint64_t StartA = SE.getUnsignedRangeMin(AS).getZExtValue();
  uint64_t StartB = SE.getUnsignedRangeMin(BS).getZExtValue();
  uint64_t EndA = StartA + WidthA;
  uint64_t EndB = StartB + WidthB;
  return std::max(StartA, StartB) >= std::min(EndA, EndB);
}

static bool getSafeRange(ScalarEvolution &SE, const SCEV *P, uint64_t Width,
                         uint64_t &Start, uint64_t &End) {
  if (SCEVConstant::classof(P)) {
    Start = SE.getUnsignedRangeMin(P).getZExtValue();
    End = Start + Width;
    return true;
  }

  int64_t Min = SE.getSignedRangeMin(P).getSExtValue();
  if (Min <= 0) {
    return false;
  }

  int64_t Max = SE.getSignedRangeMax(P).getSExtValue();
  Start = static_cast<uint64_t>(Min);
  End = static_cast<uint64_t>(Max + Width);
  return Start < End;
}

AliasResult SCEVAAResult::alias(const MemoryLocation &LocA,
                                const MemoryLocation &LocB, AAQueryInfo &AAQI,
                                const Instruction *) {
  // If either of the memory references is empty, it doesn't matter what the
  // pointer values are. This allows the code below to ignore this special
  // case.
  if (LocA.Size.isZero() || LocB.Size.isZero())
    return AliasResult::NoAlias;

  // This is SCEVAAResult. Get the SCEVs!
  const SCEV *AS = SE.getSCEV(const_cast<Value *>(LocA.Ptr));
  const SCEV *BS = SE.getSCEV(const_cast<Value *>(LocB.Ptr));

  // If they evaluate to the same expression, it's a MustAlias.
  if (AS == BS)
    return AliasResult::MustAlias;

  // If something is known about the difference between the two addresses,
  // see if it's enough to prove a NoAlias.
  if (canComputePointerDiff(SE, AS, BS)) {
    unsigned BitWidth = SE.getTypeSizeInBits(AS->getType());
    APInt ASizeInt(BitWidth, LocA.Size.hasValue()
                                 ? static_cast<uint64_t>(LocA.Size.getValue())
                                 : MemoryLocation::UnknownSize);
    APInt BSizeInt(BitWidth, LocB.Size.hasValue()
                                 ? static_cast<uint64_t>(LocB.Size.getValue())
                                 : MemoryLocation::UnknownSize);

    // Before calling getMinusSCEV(), we could try the ptrtpoint pointer
    // operands so that you can handle two pointers with different pointer
    // bases.
    const SCEV *AInt =
        SE.getPtrToIntExpr(AS, SE.getEffectiveSCEVType(AS->getType()));
    if (!isa<SCEVCouldNotCompute>(AInt))
      AS = AInt;
    const SCEV *BInt =
        SE.getPtrToIntExpr(BS, SE.getEffectiveSCEVType(BS->getType()));
    if (!isa<SCEVCouldNotCompute>(BInt))
      BS = BInt;

    // Compute the difference between the two pointers.
    const SCEV *BA = SE.getMinusSCEV(BS, AS);

    // Test whether the difference is known to be great enough that memory of
    // the given sizes don't overlap. This assumes that ASizeInt and BSizeInt
    // are non-zero, which is special-cased above.
    if (!isa<SCEVCouldNotCompute>(BA) &&
        ASizeInt.ule(SE.getUnsignedRange(BA).getUnsignedMin()) &&
        (-BSizeInt).uge(SE.getUnsignedRange(BA).getUnsignedMax()))
      return AliasResult::NoAlias;

    // Folding the subtraction while preserving range information can be tricky
    // (because of INT_MIN, etc.); if the prior test failed, swap AS and BS
    // and try again to see if things fold better that way.

    // Compute the difference between the two pointers.
    const SCEV *AB = SE.getMinusSCEV(AS, BS);

    // Test whether the difference is known to be great enough that memory of
    // the given sizes don't overlap. This assumes that ASizeInt and BSizeInt
    // are non-zero, which is special-cased above.
    if (!isa<SCEVCouldNotCompute>(AB) &&
        BSizeInt.ule(SE.getUnsignedRange(AB).getUnsignedMin()) &&
        (-ASizeInt).uge(SE.getUnsignedRange(AB).getUnsignedMax()))
      return AliasResult::NoAlias;
  }

  auto Evaluator = [&]() {
    bool HasEvaluated = false;
    uint64_t WidthA = LocA.Size.getValue();
    uint64_t WidthB = LocB.Size.getValue();
    for (unsigned i = 0, EvaluatedCount = 1; i < EvaluatedCount; ++i) {
      unsigned EvaluatedCountA = 0;
      unsigned EvaluatedCountB = 0;
      const SCEV *It =
          SE.getConstant(Type::getInt32Ty(LocA.Ptr->getContext()), i);
      const SCEV *EvaluatedAS = SE.evaluateAtIteration(AS, It, EvaluatedCountA);
      const SCEV *EvaluatedBS = SE.evaluateAtIteration(BS, It, EvaluatedCountB);

      if (!EvaluatedAS || !EvaluatedBS || !SCEVConstant::classof(EvaluatedAS) ||
          !SCEVConstant::classof(EvaluatedBS)) {
        uint64_t StartA = 0, EndA = 0;
        if (!getSafeRange(SE, EvaluatedAS ? EvaluatedAS : AS, WidthA, StartA,
                          EndA)) {
          return AliasResult::MayAlias;
        }

        uint64_t StartB = 0, EndB = 0;
        if (!getSafeRange(SE, EvaluatedBS ? EvaluatedBS : BS, WidthB, StartB,
                          EndB)) {
          return AliasResult::MayAlias;
        }

        if (std::max(StartA, StartB) < std::min(EndA, EndB)) {
          return AliasResult::MayAlias;
        }

        continue;
      }

      if (!HasEvaluated) {
        EvaluatedCount = std::max(EvaluatedCountA, EvaluatedCountB);
        HasEvaluated = true;
      }

      if (!areMemAccessesDisjoint(SE, EvaluatedAS, WidthA, EvaluatedBS,
                                  WidthB)) {
        return AliasResult::MustAlias;
      }
    }

    return AliasResult::NoAlias;
  };

  AliasResult Res = Evaluator();
  if (Res != AliasResult::MayAlias)
    return Res;

  // If ScalarEvolution can find an underlying object, form a new query.
  // The correctness of this depends on ScalarEvolution not recognizing
  // inttoptr and ptrtoint operators.
  Value *AO = GetBaseValue(AS);
  Value *BO = GetBaseValue(BS);
  if ((AO && AO != LocA.Ptr) || (BO && BO != LocB.Ptr))
    if (alias(MemoryLocation(AO ? AO : LocA.Ptr,
                             AO ? LocationSize::beforeOrAfterPointer()
                                : LocA.Size,
                             AO ? AAMDNodes() : LocA.AATags),
              MemoryLocation(BO ? BO : LocB.Ptr,
                             BO ? LocationSize::beforeOrAfterPointer()
                                : LocB.Size,
                             BO ? AAMDNodes() : LocB.AATags),
              AAQI, nullptr) == AliasResult::NoAlias)
      return AliasResult::NoAlias;

  return AliasResult::MayAlias;
}

/// Given an expression, try to find a base value.
///
/// Returns null if none was found.
Value *SCEVAAResult::GetBaseValue(const SCEV *S) {
  if (const SCEVAddRecExpr *AR = dyn_cast<SCEVAddRecExpr>(S)) {
    // In an addrec, assume that the base will be in the start, rather
    // than the step.
    return GetBaseValue(AR->getStart());
  } else if (const SCEVAddExpr *A = dyn_cast<SCEVAddExpr>(S)) {
    // If there's a pointer operand, it'll be sorted at the end of the list.
    const SCEV *Last = A->getOperand(A->getNumOperands() - 1);
    if (Last->getType()->isPointerTy())
      return GetBaseValue(Last);
  } else if (const SCEVUnknown *U = dyn_cast<SCEVUnknown>(S)) {
    // This is a leaf node.
    return U->getValue();
  }
  // No Identified object found.
  return nullptr;
}

bool SCEVAAResult::invalidate(Function &Fn, const PreservedAnalyses &PA,
                              FunctionAnalysisManager::Invalidator &Inv) {
  // We don't care if this analysis itself is preserved, it has no state. But
  // we need to check that the analyses it depends on have been.
  return Inv.invalidate<ScalarEvolutionAnalysis>(Fn, PA);
}

AnalysisKey SCEVAA::Key;

SCEVAAResult SCEVAA::run(Function &F, FunctionAnalysisManager &AM) {
  return SCEVAAResult(AM.getResult<ScalarEvolutionAnalysis>(F));
}

char SCEVAAWrapperPass::ID = 0;
INITIALIZE_PASS_BEGIN(SCEVAAWrapperPass, "scev-aa",
                      "ScalarEvolution-based Alias Analysis", false, true)
INITIALIZE_PASS_DEPENDENCY(ScalarEvolutionWrapperPass)
INITIALIZE_PASS_END(SCEVAAWrapperPass, "scev-aa",
                    "ScalarEvolution-based Alias Analysis", false, true)

FunctionPass *llvm::createSCEVAAWrapperPass() {
  return new SCEVAAWrapperPass();
}

SCEVAAWrapperPass::SCEVAAWrapperPass() : FunctionPass(ID) {
  initializeSCEVAAWrapperPassPass(*PassRegistry::getPassRegistry());
}

bool SCEVAAWrapperPass::runOnFunction(Function &F) {
  Result.reset(
      new SCEVAAResult(getAnalysis<ScalarEvolutionWrapperPass>().getSE()));
  return false;
}

void SCEVAAWrapperPass::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.setPreservesAll();
  AU.addRequired<ScalarEvolutionWrapperPass>();
}

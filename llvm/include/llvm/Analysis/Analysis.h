#ifndef LLVM_ANALYSIS_ANALYSIS_H
#define LLVM_ANALYSIS_ANALYSIS_H

namespace llvm {

class ImmutablePass;

ImmutablePass *createEverythingMustAliasLegacyPass();

} // End llvm namespace

#endif  // LLVM_ANALYSIS_ANALYSIS_H

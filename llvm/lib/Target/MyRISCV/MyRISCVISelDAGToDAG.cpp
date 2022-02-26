#include "MyRISCV.h"
#include "MyRISCVTargetMachine.h"
#include "MCTargetDesc/MyRISCVMCTargetDesc.h"
#include "llvm/CodeGen/SelectionDAGISel.h"

using namespace llvm;

namespace {

class MyRISCVDAGToDAGISel : public SelectionDAGISel {
public:
  explicit MyRISCVDAGToDAGISel(MyRISCVTargetMachine &TM)
      : SelectionDAGISel(TM) {}

  StringRef getPassName() const override {
    return "MyRISCV DAG->DAG Pattern Instruction Selection";
  }

  void Select(SDNode *N) override;

private:
  #include "MyRISCVGenDAGISel.inc"
};

} // end anonymous namespace

void MyRISCVDAGToDAGISel::Select(SDNode *N) {
  SDLoc DL(N);

  switch (N->getOpcode()) {
    case ISD::Constant: {
      int64_t Imm = cast<ConstantSDNode>(N)->getSExtValue();
      if (-2048 <= Imm && Imm <= 2047) {
        SDValue SDImm = CurDAG->getTargetConstant(Imm, DL, MVT::i32);
        SDValue SrcReg = CurDAG->getRegister(MyRISCV::X0, MVT::i32);
        SDNode *Result =
            CurDAG->getMachineNode(MyRISCV::ADDI, DL, MVT::i32, SrcReg, SDImm);
        ReplaceNode(N, Result);
        return;
      }
    }
  }

  SelectCode(N);
}

FunctionPass *llvm::createMyRISCVISelDag(MyRISCVTargetMachine &TM) {
  return new MyRISCVDAGToDAGISel(TM);
}

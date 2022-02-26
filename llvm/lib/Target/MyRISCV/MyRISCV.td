include "llvm/Target/Target.td"

include "MyRISCVRegisterInfo.td"
include "MyRISCVInstrInfo.td"
include "MyRISCVCallingConv.td"

def : ProcessorModel<"generic-rv32", NoSchedModel, []>;

def MyRISCVInstrInfo : InstrInfo;

def MyRISCV : Target {
  let InstructionSet = MyRISCVInstrInfo;
}

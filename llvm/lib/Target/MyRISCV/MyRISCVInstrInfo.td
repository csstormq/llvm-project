class RV32 : Instruction {
	let Size = 4;
	let Namespace = "MyRISCV";
	bits<32> Inst;
}

def MyRISCVRetFlag : SDNode<"MyRISCVISD::RET_FLAG", SDTNone,
                            [SDNPHasChain, SDNPOptInGlue, SDNPVariadic]>;

def simm12 : Operand<i32>, ImmLeaf<i32, [{return isInt<12>(Imm);}]>;

def ADDI : RV32 {
	let OutOperandList = (outs GPR:$rd);
	let InOperandList = (ins GPR:$rs1, simm12:$imm12);
	let AsmString = "addi $rd, $rs1, $imm12";
	bits<5> rd;
	bits<5> rs1;
	bits<12> imm12;
	let Inst{31-20} = imm12;
	let Inst{19-15} = rs1;
	let Inst{14-12} = 0b000;
	let Inst{11-7} = rd;
	let Inst{6-0} = 0b0010011;
}

def : Pat<(add GPR:$rs1, i32:$imm12), (ADDI GPR:$rs1, simm12:$imm12)>;

def JALR : RV32 {
	let OutOperandList = (outs GPR:$rd);
	let InOperandList = (ins GPR:$rs1, simm12:$imm12);
	let AsmString = "jalr $rd, ${imm12}(${rs1})";
	bits<5> rd;
	bits<5> rs1;
	bits<12> imm12;
	let Inst{31-20} = imm12;
	let Inst{19-15} = rs1;
	let Inst{14-12} = 0b000;
	let Inst{11-7} = rd;
	let Inst{6-0} = 0b1101111;
	let isCall = 1;
}

def : InstAlias<"ret", (JALR X0, X1, 0), 4>;

def PseudoRET : RV32, PseudoInstExpansion<(JALR X0, X1, 0)> {
	let OutOperandList = (outs);
	let InOperandList = (ins);
	let Pattern = [(MyRISCVRetFlag)];
	let isPseudo = 1;
	let isReturn = 1;
	let isTerminator = 1;
}

// just for testing
def ADD : RV32 {
	let OutOperandList = (outs GPR:$rd);
	let InOperandList = (ins GPR:$rs1, GPR:$rs2);
	let AsmString = "add $rd, $rs1, $rs2";
	bits<5> rd;
	bits<5> rs1;
	bits<12> rs2;
	let Inst{31-20} = rs2;
	let Inst{19-15} = rs1;
	let Inst{14-12} = 0b000;
	let Inst{11-7} = rd;
	let Inst{6-0} = 0b0010011;
}

def SDT_TEST : SDTypeProfile<1, 2, [
  SDTCisVTSmallerThanOp<2, 1>
]>;

def TEST_SDNode : SDNode<"MyRISCVISD::TEST", SDT_TEST>;

def : Pat<(i32 (TEST_SDNode i32:$rs1, i16:$rs2)), (ADD GPR:$rs1, GPR:$rs2)>;

def : Pat<(v32i1 (TEST_SDNode v32i1:$rs1, v16i1:$rs2)), (ADD GPR:$rs1, GPR:$rs2)>;

def : Pat<(f16 (TEST_SDNode f32:$rs1, f16:$rs2)), (ADD GPR:$rs1, GPR:$rs2)>;

def : Pat<(v2i16 (TEST_SDNode v2i16:$rs1, v1i16:$rs2)), (ADD GPR:$rs1, GPR:$rs2)>;

def : Pat<(v2f16 (TEST_SDNode v2f16:$rs1, v1f16:$rs2)), (ADD GPR:$rs1, GPR:$rs2)>;

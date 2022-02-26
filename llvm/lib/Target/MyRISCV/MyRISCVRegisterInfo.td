class MyRISCVReg<bits<5> enc, string name, list<string> alt = []>
		: Register<name, alt> {
	let HWEncoding{4-0} = enc;
	let Namespace = "MyRISCV";
}

def ABIRegAltName : RegAltNameIndex;

let RegAltNameIndices = [ABIRegAltName] in {
	def X0  : MyRISCVReg<0,  "x0",  ["zero"]>;
	def X1  : MyRISCVReg<1,  "x1",  ["ra"]>;
	def X2  : MyRISCVReg<2,  "x2",  ["sp"]>;
	def X3  : MyRISCVReg<3,  "x3",  ["gp"]>;
	def X4  : MyRISCVReg<4,  "x4",  ["tp"]>;
	def X5  : MyRISCVReg<5,  "x5",  ["t0"]>;
	def X6  : MyRISCVReg<6,  "x6",  ["t1"]>;
	def X7  : MyRISCVReg<7,  "x7",  ["t2"]>;
	def X8  : MyRISCVReg<8,  "x8",  ["s0", "fp"]>;
	def X9  : MyRISCVReg<9,  "x9",  ["s1"]>;
	def X10 : MyRISCVReg<10, "x10", ["a0"]>;
	def X11 : MyRISCVReg<11, "x11", ["a1"]>;
	def X12 : MyRISCVReg<12, "x12", ["a2"]>;
	def X13 : MyRISCVReg<13, "x13", ["a3"]>;
	def X14 : MyRISCVReg<14, "x14", ["a4"]>;
	def X15 : MyRISCVReg<15, "x15", ["a5"]>;
	def X16 : MyRISCVReg<16, "x16", ["a6"]>;
	def X17 : MyRISCVReg<17, "x17", ["a7"]>;
	def X18 : MyRISCVReg<18, "x18", ["s2"]>;
	def X19 : MyRISCVReg<19, "x19", ["s3"]>;
	def X20 : MyRISCVReg<20, "x20", ["s4"]>;
	def X21 : MyRISCVReg<21, "x21", ["s5"]>;
	def X22 : MyRISCVReg<22, "x22", ["s6"]>;
	def X23 : MyRISCVReg<23, "x23", ["s7"]>;
	def X24 : MyRISCVReg<24, "x24", ["s8"]>;
	def X25 : MyRISCVReg<25, "x25", ["s9"]>;
	def X26 : MyRISCVReg<26, "x26", ["s10"]>;
	def X27 : MyRISCVReg<27, "x27", ["s11"]>;
	def X28 : MyRISCVReg<28, "x28", ["t3"]>;
	def X29 : MyRISCVReg<29, "x29", ["t4"]>;
	def X30 : MyRISCVReg<30, "x30", ["t5"]>;
	def X31 : MyRISCVReg<31, "x31", ["t6"]>;
}

def GPR : RegisterClass<"MyRISCV", [i32], 32, (add
	(sequence "X%u", 10, 17),
	(sequence "X%u", 5, 7),
	(sequence "X%u", 28, 31),
	(sequence "X%u", 8, 9),
	(sequence "X%u", 18, 27),
	(sequence "X%u", 0, 4)
)>;

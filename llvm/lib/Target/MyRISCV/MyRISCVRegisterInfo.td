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

let RegAltNameIndices = [ABIRegAltName] in {
  def F0_F  : MyRISCVReg<0,  "f0",  ["ft0"]>;
  def F1_F  : MyRISCVReg<1,  "f1",  ["ft1"]>;
  def F2_F  : MyRISCVReg<2,  "f2",  ["ft2"]>;
  def F3_F  : MyRISCVReg<3,  "f3",  ["ft3"]>;
  def F4_F  : MyRISCVReg<4,  "f4",  ["ft4"]>;
  def F5_F  : MyRISCVReg<5,  "f5",  ["ft5"]>;
  def F6_F  : MyRISCVReg<6,  "f6",  ["ft6"]>;
  def F7_F  : MyRISCVReg<7,  "f7",  ["ft7"]>;
  def F8_F  : MyRISCVReg<8,  "f8",  ["fs0"]>;
  def F9_F  : MyRISCVReg<9,  "f9",  ["fs1"]>;
  def F10_F : MyRISCVReg<10, "f10", ["fa0"]>;
  def F11_F : MyRISCVReg<11, "f11", ["fa1"]>;
  def F12_F : MyRISCVReg<12, "f12", ["fa2"]>;
  def F13_F : MyRISCVReg<13, "f13", ["fa3"]>;
  def F14_F : MyRISCVReg<14, "f14", ["fa4"]>;
  def F15_F : MyRISCVReg<15, "f15", ["fa5"]>;
  def F16_F : MyRISCVReg<16, "f16", ["fa6"]>;
  def F17_F : MyRISCVReg<17, "f17", ["fa7"]>;
  def F18_F : MyRISCVReg<18, "f18", ["fs2"]>;
  def F19_F : MyRISCVReg<19, "f19", ["fs3"]>;
  def F20_F : MyRISCVReg<20, "f20", ["fs4"]>;
  def F21_F : MyRISCVReg<21, "f21", ["fs5"]>;
  def F22_F : MyRISCVReg<22, "f22", ["fs6"]>;
  def F23_F : MyRISCVReg<23, "f23", ["fs7"]>;
  def F24_F : MyRISCVReg<24, "f24", ["fs8"]>;
  def F25_F : MyRISCVReg<25, "f25", ["fs9"]>;
  def F26_F : MyRISCVReg<26, "f26", ["fs10"]>;
  def F27_F : MyRISCVReg<27, "f27", ["fs11"]>;
  def F28_F : MyRISCVReg<28, "f28", ["ft8"]>;
  def F29_F : MyRISCVReg<29, "f29", ["ft9"]>;
  def F30_F : MyRISCVReg<30, "f30", ["ft10"]>;
  def F31_F : MyRISCVReg<31, "f31", ["ft11"]>;
}

def FPR32 : RegisterClass<"MyRISCV", [f32], 32, (add
  (sequence "F%u_F", 0, 7),
  (sequence "F%u_F", 10, 17),
  (sequence "F%u_F", 28, 31),
  (sequence "F%u_F", 8, 9),
  (sequence "F%u_F", 18, 27)
)>;

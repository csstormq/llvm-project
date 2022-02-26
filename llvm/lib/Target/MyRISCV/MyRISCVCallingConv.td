def RetCC_MyRISCV : CallingConv<[
	CCIfType<[i1, i8, i16, i32], CCAssignToReg<[X10, X11]>>,
	CCIfType<[i32], CCAssignToStack<4, 4>>,
]>;

def CC_MyRISCV : CallingConv<[
	CCIfType<[i1, i8, i16, i32], CCAssignToReg<[X10, X11, X12, X13, X14, X15, X16, X17]>>,
	CCIfType<[i32], CCAssignToStack<4, 4>>,
]>;

def CC_Save : CalleeSavedRegs<(add X2, X8, X9, (sequence "X%u", 18, 27))>;

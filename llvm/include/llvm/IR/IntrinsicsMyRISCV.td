let TargetPrefix = "myriscv" in {
  def int_myriscv_fptosi : Intrinsic<[llvm_anyint_ty],
                                     [llvm_anyfloat_ty],
                                     [IntrNoMem, IntrHasSideEffects]>;

  def int_myriscv_test1 : Intrinsic<[llvm_anyint_ty],
                                    [llvm_anyfloat_ty],
                                    []>;

  def int_myriscv_test2 : Intrinsic<[llvm_anyint_ty],
                                    [llvm_anyfloat_ty],
                                    [IntrNoMem]>;

  def int_myriscv_test3 : Intrinsic<[llvm_anyint_ty],
                                    [llvm_anyfloat_ty],
                                    [IntrHasSideEffects]>;

  def int_myriscv_test4 : Intrinsic<[llvm_anyint_ty],
                                    [llvm_anyfloat_ty],
                                    [IntrReadMem]>;

  def int_myriscv_test5 : Intrinsic<[llvm_anyint_ty],
                                    [llvm_anyfloat_ty],
                                    [IntrWriteMem]>;

  def int_myriscv_test6 : Intrinsic<[llvm_anyint_ty],
                                    [llvm_anyfloat_ty],
                                    [IntrReadMem, IntrHasSideEffects]>;

  def int_myriscv_test7 : Intrinsic<[llvm_anyint_ty],
                                    [llvm_anyfloat_ty],
                                    [IntrWriteMem, IntrHasSideEffects]>;
}

; RUN: llc -march=myriscv32 < %s | FileCheck -check-prefix=RV32I -color %s

define i32 @fptosi_f32_to_i32(float %a) {
; RV32I-LABEL:fptosi_f32_to_i32:
; RV32I:      # %bb.0:
; RV32I-NEXT:         fptosi a0, fa0
; RV32I-NEXT:         ret
  %1 = call i32 @llvm.myriscv.fptosi.i32.f32(float %a)
  ret i32 %1
}
declare i32 @llvm.myriscv.fptosi.i32.f32(float)

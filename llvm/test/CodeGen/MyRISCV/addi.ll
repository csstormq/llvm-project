; RUN: llc -march=myriscv32 < %s | FileCheck -check-prefix=RV32I -color %s

define i32 @ret_min_value_of_simm12() {
; RV32I-LABEL:ret_min_value_of_simm12:
; RV32I:      # %bb.0:
; RV32I-NEXT:         addi a0, zero, -2048
; RV32I-NEXT:         ret
  ret i32 -2048
}

define i32 @ret_max_value_of_simm12() {
; RV32I-LABEL:ret_max_value_of_simm12:
; RV32I:      # %bb.0:
; RV32I-NEXT:         addi a0, zero, 2047
; RV32I-NEXT:         ret
  ret i32 2047
}

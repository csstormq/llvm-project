//===-- Implementation header for isnan -------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_SRC_MATH_ISNAN_H
#define LLVM_LIBC_SRC_MATH_ISNAN_H

namespace LIBC_NAMESPACE {

int isnan(double x);

} // namespace LIBC_NAMESPACE

#endif // LLVM_LIBC_SRC_MATH_ISNAN_H

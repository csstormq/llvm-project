//===-- Implementation header of fopencookie --------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_SRC_STDIO_FOPENCOOKIE_H
#define LLVM_LIBC_SRC_STDIO_FOPENCOOKIE_H

#include "hdr/types/FILE.h"
#include "hdr/types/cookie_io_functions_t.h"

namespace LIBC_NAMESPACE {

::FILE *fopencookie(void *cookie, const char *__restrict mode,
                    cookie_io_functions_t desc);

} // namespace LIBC_NAMESPACE

#endif // LLVM_LIBC_SRC_STDIO_FOPENCOOKIE_H

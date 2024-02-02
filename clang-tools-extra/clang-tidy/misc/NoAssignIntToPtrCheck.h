//===--- NoAssignIntToPtrCheck.h - clang-tidy -------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_MISC_NOASSIGNINTTOPTRCHECK_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_MISC_NOASSIGNINTTOPTRCHECK_H

#include "../ClangTidyCheck.h"

namespace clang::tidy::misc {

// Detect vulnerability CWE-587
// CWE-587 vulnerability means that assigning a constant address other than
// 'NULL' or '0' to a pointer is considered a bad practice. Using a fixed
// address is not portable, because this address will not be valid in all
// environments or platforms.

/// For the user-facing documentation see:
/// http://clang.llvm.org/extra/clang-tidy/checks/misc/no-assign-int-to-ptr.html
class NoAssignIntToPtrCheck : public ClangTidyCheck {
public:
  NoAssignIntToPtrCheck(StringRef Name, ClangTidyContext *Context)
      : ClangTidyCheck(Name, Context) {}
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;
};

} // namespace clang::tidy::misc

#endif // LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_MISC_NOASSIGNINTTOPTRCHECK_H

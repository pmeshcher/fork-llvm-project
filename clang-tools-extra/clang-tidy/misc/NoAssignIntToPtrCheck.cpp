//===--- NoAssignIntToPtrCheck.cpp - clang-tidy -------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//

//===----------------------------------------------------------------------===//

#include "NoAssignIntToPtrCheck.h"
#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Basic/SourceLocation.h"
#include "llvm/ADT/StringRef.h"

using namespace clang::ast_matchers;

namespace {
  llvm::StringRef MatchBind =      "CastConstNotNullAddrToPointer";
  llvm::StringRef MatchUnionBind = "UnionPossibleCastDeclaration";
}

namespace clang::tidy::misc {
  void NoAssignIntToPtrCheck::registerMatchers(MatchFinder *Finder) {
    auto CastTypes = anyOf(hasCastKind(CK_IntegralToPointer), 
                            hasCastKind(CK_Dependent));
    auto DescendantNonZeroInteger = hasDescendant(integerLiteral(unless(equals(0))));
    Finder->addMatcher(explicitCastExpr(CastTypes,
                                        DescendantNonZeroInteger).bind(MatchBind),
                                        this);

    auto PointerType = hasType(pointerType());
    Finder->addMatcher(cxxRecordDecl(allOf(isUnion(),
                                     hasDescendant(fieldDecl(PointerType)),
                                     hasDescendant(fieldDecl(unless(PointerType))))).bind(MatchUnionBind),
                                     this);
  }

  void NoAssignIntToPtrCheck::check(const MatchFinder::MatchResult &Result) {
    SourceLocation InsertionLocation;

    if(const auto MatchedExpr = Result.Nodes.getNodeAs<Expr>(MatchBind)) {
      InsertionLocation = MatchedExpr->getBeginLoc();
      diag(InsertionLocation, "Assigning a constant address other then NULL and 0 is a bad practice. CWE-587");
    }
    else if(const auto MatchedDecl = Result.Nodes.getNodeAs<NamedDecl>(MatchUnionBind)) {
      InsertionLocation = MatchedDecl->getBeginLoc();
      diag(InsertionLocation, "This union has a pointer field. It can cause assigning constant address to pointer. CWE-587");
    }
  }
}
//===------- ItaniumCXXABI.cpp - AST support for the Itanium C++ ABI ------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This provides C++ AST support targeting the Itanium C++ ABI, which is
// documented at:
//  http://www.codesourcery.com/public/cxx-abi/abi.html
//  http://www.codesourcery.com/public/cxx-abi/abi-eh.html
//
// It also supports the closely-related ARM C++ ABI, documented at:
// http://infocenter.arm.com/help/topic/com.arm.doc.ihi0041c/IHI0041C_cppabi.pdf
//
//===----------------------------------------------------------------------===//

#include "CXXABI.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/RecordLayout.h"
#include "clang/AST/Type.h"
#include "clang/Basic/TargetInfo.h"

using namespace clang;

namespace {
class ItaniumCXXABI : public CXXABI {
protected:
  ASTContext &Context;
public:
  ItaniumCXXABI(ASTContext &Ctx) : Context(Ctx) { }

  std::pair<uint64_t, unsigned>
  getMemberPointerWidthAndAlign(const MemberPointerType *MPT) const {
    const TargetInfo &Target = Context.getTargetInfo();
    TargetInfo::IntType PtrDiff = Target.getPtrDiffType(0);
    uint64_t Width = Target.getTypeWidth(PtrDiff);
    unsigned Align = Target.getTypeAlign(PtrDiff);
    // Treeki's CW/PPC mod:
    //   Added an extra field.
    if (MPT->getPointeeType()->isFunctionType())
      Width = 3 * Width;
    return std::make_pair(Width, Align);
  }

  CallingConv getDefaultMethodCallConv(bool isVariadic) const {
    return CC_C;
  }

  // We cheat and just check that the class has a vtable pointer, and that it's
  // only big enough to have a vtable pointer and nothing more (or less).
  bool isNearlyEmpty(const CXXRecordDecl *RD) const {

    // Check that the class has a vtable pointer.
    if (!RD->isDynamicClass())
      return false;

    const ASTRecordLayout &Layout = Context.getASTRecordLayout(RD);
    CharUnits PointerSize = 
      Context.toCharUnitsFromBits(Context.getTargetInfo().getPointerWidth(0));
    return Layout.getNonVirtualSize() == PointerSize;
  }
};

class ARMCXXABI : public ItaniumCXXABI {
public:
  ARMCXXABI(ASTContext &Ctx) : ItaniumCXXABI(Ctx) { }
};
}

CXXABI *clang::CreateItaniumCXXABI(ASTContext &Ctx) {
  return new ItaniumCXXABI(Ctx);
}

CXXABI *clang::CreateARMCXXABI(ASTContext &Ctx) {
  return new ARMCXXABI(Ctx);
}

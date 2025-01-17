//===--- MicrosoftMangle.cpp - Microsoft Visual C++ Name Mangling ---------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This provides C++ name mangling targeting the Microsoft Visual C++ ABI.
//
//===----------------------------------------------------------------------===//

#include "clang/AST/Mangle.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Attr.h"
#include "clang/AST/CharUnits.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/DeclObjC.h"
#include "clang/AST/DeclTemplate.h"
#include "clang/AST/ExprCXX.h"
#include "clang/Basic/ABI.h"
#include "clang/Basic/DiagnosticOptions.h"
#include "clang/Basic/TargetInfo.h"
#include "llvm/ADT/StringMap.h"

using namespace clang;

namespace {

static const FunctionDecl *getStructor(const FunctionDecl *fn) {
  if (const FunctionTemplateDecl *ftd = fn->getPrimaryTemplate())
    return ftd->getTemplatedDecl();

  return fn;
}

/// MicrosoftCXXNameMangler - Manage the mangling of a single name for the
/// Microsoft Visual C++ ABI.
class MicrosoftCXXNameMangler {
  MangleContext &Context;
  raw_ostream &Out;

  /// The "structor" is the top-level declaration being mangled, if
  /// that's not a template specialization; otherwise it's the pattern
  /// for that specialization.
  const NamedDecl *Structor;
  unsigned StructorType;

  typedef llvm::StringMap<unsigned> BackRefMap;
  BackRefMap NameBackReferences;
  bool UseNameBackReferences;

  typedef llvm::DenseMap<void*, unsigned> ArgBackRefMap;
  ArgBackRefMap TypeBackReferences;

  ASTContext &getASTContext() const { return Context.getASTContext(); }

  // FIXME: If we add support for __ptr32/64 qualifiers, then we should push
  // this check into mangleQualifiers().
  const bool PointersAre64Bit;

public:
  enum QualifierMangleMode { QMM_Drop, QMM_Mangle, QMM_Escape, QMM_Result };

  MicrosoftCXXNameMangler(MangleContext &C, raw_ostream &Out_)
    : Context(C), Out(Out_),
      Structor(0), StructorType(-1),
      UseNameBackReferences(true),
      PointersAre64Bit(C.getASTContext().getTargetInfo().getPointerWidth(0) ==
                       64) { }

  MicrosoftCXXNameMangler(MangleContext &C, raw_ostream &Out_,
                          const CXXDestructorDecl *D, CXXDtorType Type)
    : Context(C), Out(Out_),
      Structor(getStructor(D)), StructorType(Type),
      UseNameBackReferences(true),
      PointersAre64Bit(C.getASTContext().getTargetInfo().getPointerWidth(0) ==
                       64) { }

  raw_ostream &getStream() const { return Out; }

  void mangle(const NamedDecl *D, StringRef Prefix = "\01?");
  void mangleName(const NamedDecl *ND);
  void mangleFunctionEncoding(const FunctionDecl *FD);
  void mangleVariableEncoding(const VarDecl *VD);
  void mangleNumber(int64_t Number);
  void mangleNumber(const llvm::APSInt &Value);
  void mangleType(QualType T, SourceRange Range,
                  QualifierMangleMode QMM = QMM_Mangle);

private:
  void disableBackReferences() { UseNameBackReferences = false; }
  void mangleUnqualifiedName(const NamedDecl *ND) {
    mangleUnqualifiedName(ND, ND->getDeclName());
  }
  void mangleUnqualifiedName(const NamedDecl *ND, DeclarationName Name);
  void mangleSourceName(const IdentifierInfo *II);
  void manglePostfix(const DeclContext *DC, bool NoFunction=false);
  void mangleOperatorName(OverloadedOperatorKind OO, SourceLocation Loc);
  void mangleCXXDtorType(CXXDtorType T);
  void mangleQualifiers(Qualifiers Quals, bool IsMember);
  void manglePointerQualifiers(Qualifiers Quals);

  void mangleUnscopedTemplateName(const TemplateDecl *ND);
  void mangleTemplateInstantiationName(const TemplateDecl *TD,
                                      const TemplateArgumentList &TemplateArgs);
  void mangleObjCMethodName(const ObjCMethodDecl *MD);
  void mangleLocalName(const FunctionDecl *FD);

  void mangleArgumentType(QualType T, SourceRange Range);

  // Declare manglers for every type class.
#define ABSTRACT_TYPE(CLASS, PARENT)
#define NON_CANONICAL_TYPE(CLASS, PARENT)
#define TYPE(CLASS, PARENT) void mangleType(const CLASS##Type *T, \
                                            SourceRange Range);
#include "clang/AST/TypeNodes.def"
#undef ABSTRACT_TYPE
#undef NON_CANONICAL_TYPE
#undef TYPE
  
  void mangleType(const TagType*);
  void mangleFunctionType(const FunctionType *T, const FunctionDecl *D,
                          bool IsStructor, bool IsInstMethod);
  void mangleDecayedArrayType(const ArrayType *T, bool IsGlobal);
  void mangleArrayType(const ArrayType *T, Qualifiers Quals);
  void mangleFunctionClass(const FunctionDecl *FD);
  void mangleCallingConvention(const FunctionType *T, bool IsInstMethod = false);
  void mangleIntegerLiteral(const llvm::APSInt &Number, bool IsBoolean);
  void mangleExpression(const Expr *E);
  void mangleThrowSpecification(const FunctionProtoType *T);

  void mangleTemplateArgs(const TemplateDecl *TD,
                          const TemplateArgumentList &TemplateArgs);

};

/// MicrosoftMangleContext - Overrides the default MangleContext for the
/// Microsoft Visual C++ ABI.
class MicrosoftMangleContext : public MangleContext {
public:
  MicrosoftMangleContext(ASTContext &Context,
                   DiagnosticsEngine &Diags) : MangleContext(Context, Diags) { }
  virtual bool shouldMangleDeclName(const NamedDecl *D);
  virtual void mangleName(const NamedDecl *D, raw_ostream &Out);
  virtual void mangleThunk(const CXXMethodDecl *MD,
                           const ThunkInfo &Thunk,
                           raw_ostream &);
  virtual void mangleCXXDtorThunk(const CXXDestructorDecl *DD, CXXDtorType Type,
                                  const ThisAdjustment &ThisAdjustment,
                                  raw_ostream &);
  virtual void mangleCXXVTable(const CXXRecordDecl *RD,
                               raw_ostream &);
  virtual void mangleCXXVTT(const CXXRecordDecl *RD,
                            raw_ostream &);
  virtual void mangleCXXVBTable(const CXXRecordDecl *Derived,
                                ArrayRef<const CXXRecordDecl *> BasePath,
                                raw_ostream &Out);
  virtual void mangleCXXCtorVTable(const CXXRecordDecl *RD, int64_t Offset,
                                   const CXXRecordDecl *Type,
                                   raw_ostream &);
  virtual void mangleCXXRTTI(QualType T, raw_ostream &);
  virtual void mangleCXXRTTIName(QualType T, raw_ostream &);
  virtual void mangleCXXCtor(const CXXConstructorDecl *D, CXXCtorType Type,
                             raw_ostream &);
  virtual void mangleCXXDtor(const CXXDestructorDecl *D, CXXDtorType Type,
                             raw_ostream &);
  virtual void mangleReferenceTemporary(const clang::VarDecl *,
                                        raw_ostream &);
};

}

static bool isInCLinkageSpecification(const Decl *D) {
  D = D->getCanonicalDecl();
  for (const DeclContext *DC = D->getDeclContext();
       !DC->isTranslationUnit(); DC = DC->getParent()) {
    if (const LinkageSpecDecl *Linkage = dyn_cast<LinkageSpecDecl>(DC))
      return Linkage->getLanguage() == LinkageSpecDecl::lang_c;
  }

  return false;
}

bool MicrosoftMangleContext::shouldMangleDeclName(const NamedDecl *D) {
  // In C, functions with no attributes never need to be mangled. Fastpath them.
  if (!getASTContext().getLangOpts().CPlusPlus && !D->hasAttrs())
    return false;

  // Any decl can be declared with __asm("foo") on it, and this takes precedence
  // over all other naming in the .o file.
  if (D->hasAttr<AsmLabelAttr>())
    return true;

  // Clang's "overloadable" attribute extension to C/C++ implies name mangling
  // (always) as does passing a C++ member function and a function
  // whose name is not a simple identifier.
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (FD && (FD->hasAttr<OverloadableAttr>() || isa<CXXMethodDecl>(FD) ||
             !FD->getDeclName().isIdentifier()))
    return true;

  // Otherwise, no mangling is done outside C++ mode.
  if (!getASTContext().getLangOpts().CPlusPlus)
    return false;

  // Variables at global scope with internal linkage are not mangled.
  if (!FD) {
    const DeclContext *DC = D->getDeclContext();
    if (DC->isTranslationUnit() && D->getFormalLinkage() == InternalLinkage)
      return false;
  }

  // C functions and "main" are not mangled.
  if ((FD && FD->isMain()) || isInCLinkageSpecification(D))
    return false;

  return true;
}

void MicrosoftCXXNameMangler::mangle(const NamedDecl *D,
                                     StringRef Prefix) {
  // MSVC doesn't mangle C++ names the same way it mangles extern "C" names.
  // Therefore it's really important that we don't decorate the
  // name with leading underscores or leading/trailing at signs. So, by
  // default, we emit an asm marker at the start so we get the name right.
  // Callers can override this with a custom prefix.

  // Any decl can be declared with __asm("foo") on it, and this takes precedence
  // over all other naming in the .o file.
  if (const AsmLabelAttr *ALA = D->getAttr<AsmLabelAttr>()) {
    // If we have an asm name, then we use it as the mangling.
    Out << '\01' << ALA->getLabel();
    return;
  }

  // <mangled-name> ::= ? <name> <type-encoding>
  Out << Prefix;
  mangleName(D);
  if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(D))
    mangleFunctionEncoding(FD);
  else if (const VarDecl *VD = dyn_cast<VarDecl>(D))
    mangleVariableEncoding(VD);
  else {
    // TODO: Fields? Can MSVC even mangle them?
    // Issue a diagnostic for now.
    DiagnosticsEngine &Diags = Context.getDiags();
    unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
      "cannot mangle this declaration yet");
    Diags.Report(D->getLocation(), DiagID)
      << D->getSourceRange();
  }
}

void MicrosoftCXXNameMangler::mangleFunctionEncoding(const FunctionDecl *FD) {
  // <type-encoding> ::= <function-class> <function-type>

  // Don't mangle in the type if this isn't a decl we should typically mangle.
  if (!Context.shouldMangleDeclName(FD))
    return;
  
  // We should never ever see a FunctionNoProtoType at this point.
  // We don't even know how to mangle their types anyway :).
  const FunctionProtoType *FT = FD->getType()->castAs<FunctionProtoType>();

  bool InStructor = false, InInstMethod = false;
  const CXXMethodDecl *MD = dyn_cast<CXXMethodDecl>(FD);
  if (MD) {
    if (MD->isInstance())
      InInstMethod = true;
    if (isa<CXXConstructorDecl>(MD) || isa<CXXDestructorDecl>(MD))
      InStructor = true;
  }

  // First, the function class.
  mangleFunctionClass(FD);

  mangleFunctionType(FT, FD, InStructor, InInstMethod);
}

void MicrosoftCXXNameMangler::mangleVariableEncoding(const VarDecl *VD) {
  // <type-encoding> ::= <storage-class> <variable-type>
  // <storage-class> ::= 0  # private static member
  //                 ::= 1  # protected static member
  //                 ::= 2  # public static member
  //                 ::= 3  # global
  //                 ::= 4  # static local
  
  // The first character in the encoding (after the name) is the storage class.
  if (VD->isStaticDataMember()) {
    // If it's a static member, it also encodes the access level.
    switch (VD->getAccess()) {
      default:
      case AS_private: Out << '0'; break;
      case AS_protected: Out << '1'; break;
      case AS_public: Out << '2'; break;
    }
  }
  else if (!VD->isStaticLocal())
    Out << '3';
  else
    Out << '4';
  // Now mangle the type.
  // <variable-type> ::= <type> <cvr-qualifiers>
  //                 ::= <type> <pointee-cvr-qualifiers> # pointers, references
  // Pointers and references are odd. The type of 'int * const foo;' gets
  // mangled as 'QAHA' instead of 'PAHB', for example.
  TypeLoc TL = VD->getTypeSourceInfo()->getTypeLoc();
  QualType Ty = TL.getType();
  if (Ty->isPointerType() || Ty->isReferenceType()) {
    mangleType(Ty, TL.getSourceRange(), QMM_Drop);
    mangleQualifiers(Ty->getPointeeType().getQualifiers(), false);
  } else if (const ArrayType *AT = getASTContext().getAsArrayType(Ty)) {
    // Global arrays are funny, too.
    mangleDecayedArrayType(AT, true);
    if (AT->getElementType()->isArrayType())
      Out << 'A';
    else
      mangleQualifiers(Ty.getQualifiers(), false);
  } else {
    mangleType(Ty, TL.getSourceRange(), QMM_Drop);
    mangleQualifiers(Ty.getLocalQualifiers(), false);
  }
}

void MicrosoftCXXNameMangler::mangleName(const NamedDecl *ND) {
  // <name> ::= <unscoped-name> {[<named-scope>]+ | [<nested-name>]}? @
  const DeclContext *DC = ND->getDeclContext();

  // Always start with the unqualified name.
  mangleUnqualifiedName(ND);    

  // If this is an extern variable declared locally, the relevant DeclContext
  // is that of the containing namespace, or the translation unit.
  if (isa<FunctionDecl>(DC) && ND->hasLinkage())
    while (!DC->isNamespace() && !DC->isTranslationUnit())
      DC = DC->getParent();

  manglePostfix(DC);

  // Terminate the whole name with an '@'.
  Out << '@';
}

void MicrosoftCXXNameMangler::mangleNumber(int64_t Number) {
  llvm::APSInt APSNumber(/*BitWidth=*/64, /*isUnsigned=*/false);
  APSNumber = Number;
  mangleNumber(APSNumber);
}

void MicrosoftCXXNameMangler::mangleNumber(const llvm::APSInt &Value) {
  // <number> ::= [?] <decimal digit> # 1 <= Number <= 10
  //          ::= [?] <hex digit>+ @ # 0 or > 9; A = 0, B = 1, etc...
  //          ::= [?] @ # 0 (alternate mangling, not emitted by VC)
  if (Value.isSigned() && Value.isNegative()) {
    Out << '?';
    mangleNumber(llvm::APSInt(Value.abs()));
    return;
  }
  llvm::APSInt Temp(Value);
  // There's a special shorter mangling for 0, but Microsoft
  // chose not to use it. Instead, 0 gets mangled as "A@". Oh well...
  if (Value.uge(1) && Value.ule(10)) {
    --Temp;
    Temp.print(Out, false);
  } else {
    // We have to build up the encoding in reverse order, so it will come
    // out right when we write it out.
    char Encoding[64];
    char *EndPtr = Encoding+sizeof(Encoding);
    char *CurPtr = EndPtr;
    llvm::APSInt NibbleMask(Value.getBitWidth(), Value.isUnsigned());
    NibbleMask = 0xf;
    do {
      *--CurPtr = 'A' + Temp.And(NibbleMask).getLimitedValue(0xf);
      Temp = Temp.lshr(4);
    } while (Temp != 0);
    Out.write(CurPtr, EndPtr-CurPtr);
    Out << '@';
  }
}

static const TemplateDecl *
isTemplate(const NamedDecl *ND, const TemplateArgumentList *&TemplateArgs) {
  // Check if we have a function template.
  if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(ND)){
    if (const TemplateDecl *TD = FD->getPrimaryTemplate()) {
      TemplateArgs = FD->getTemplateSpecializationArgs();
      return TD;
    }
  }

  // Check if we have a class template.
  if (const ClassTemplateSpecializationDecl *Spec =
        dyn_cast<ClassTemplateSpecializationDecl>(ND)) {
    TemplateArgs = &Spec->getTemplateArgs();
    return Spec->getSpecializedTemplate();
  }

  return 0;
}

void
MicrosoftCXXNameMangler::mangleUnqualifiedName(const NamedDecl *ND,
                                               DeclarationName Name) {
  //  <unqualified-name> ::= <operator-name>
  //                     ::= <ctor-dtor-name>
  //                     ::= <source-name>
  //                     ::= <template-name>

  // Check if we have a template.
  const TemplateArgumentList *TemplateArgs = 0;
  if (const TemplateDecl *TD = isTemplate(ND, TemplateArgs)) {
    // We have a template.
    // Here comes the tricky thing: if we need to mangle something like
    //   void foo(A::X<Y>, B::X<Y>),
    // the X<Y> part is aliased. However, if you need to mangle
    //   void foo(A::X<A::Y>, A::X<B::Y>),
    // the A::X<> part is not aliased.
    // That said, from the mangler's perspective we have a structure like this:
    //   namespace[s] -> type[ -> template-parameters]
    // but from the Clang perspective we have
    //   type [ -> template-parameters]
    //      \-> namespace[s]
    // What we do is we create a new mangler, mangle the same type (without
    // a namespace suffix) using the extra mangler with back references
    // disabled (to avoid infinite recursion) and then use the mangled type
    // name as a key to check the mangling of different types for aliasing.

    std::string BackReferenceKey;
    BackRefMap::iterator Found;
    if (UseNameBackReferences) {
      llvm::raw_string_ostream Stream(BackReferenceKey);
      MicrosoftCXXNameMangler Extra(Context, Stream);
      Extra.disableBackReferences();
      Extra.mangleUnqualifiedName(ND, Name);
      Stream.flush();

      Found = NameBackReferences.find(BackReferenceKey);
    }
    if (!UseNameBackReferences || Found == NameBackReferences.end()) {
      mangleTemplateInstantiationName(TD, *TemplateArgs);
      if (UseNameBackReferences && NameBackReferences.size() < 10) {
        size_t Size = NameBackReferences.size();
        NameBackReferences[BackReferenceKey] = Size;
      }
    } else {
      Out << Found->second;
    }
    return;
  }

  switch (Name.getNameKind()) {
    case DeclarationName::Identifier: {
      if (const IdentifierInfo *II = Name.getAsIdentifierInfo()) {
        mangleSourceName(II);
        break;
      }
      
      // Otherwise, an anonymous entity.  We must have a declaration.
      assert(ND && "mangling empty name without declaration");
      
      if (const NamespaceDecl *NS = dyn_cast<NamespaceDecl>(ND)) {
        if (NS->isAnonymousNamespace()) {
          Out << "?A@";
          break;
        }
      }
      
      // We must have an anonymous struct.
      const TagDecl *TD = cast<TagDecl>(ND);
      if (const TypedefNameDecl *D = TD->getTypedefNameForAnonDecl()) {
        assert(TD->getDeclContext() == D->getDeclContext() &&
               "Typedef should not be in another decl context!");
        assert(D->getDeclName().getAsIdentifierInfo() &&
               "Typedef was not named!");
        mangleSourceName(D->getDeclName().getAsIdentifierInfo());
        break;
      }

      // When VC encounters an anonymous type with no tag and no typedef,
      // it literally emits '<unnamed-tag>'.
      Out << "<unnamed-tag>";
      break;
    }
      
    case DeclarationName::ObjCZeroArgSelector:
    case DeclarationName::ObjCOneArgSelector:
    case DeclarationName::ObjCMultiArgSelector:
      llvm_unreachable("Can't mangle Objective-C selector names here!");
      
    case DeclarationName::CXXConstructorName:
      if (ND == Structor) {
        assert(StructorType == Ctor_Complete &&
               "Should never be asked to mangle a ctor other than complete");
      }
      Out << "?0";
      break;
      
    case DeclarationName::CXXDestructorName:
      if (ND == Structor)
        // If the named decl is the C++ destructor we're mangling,
        // use the type we were given.
        mangleCXXDtorType(static_cast<CXXDtorType>(StructorType));
      else
        // Otherwise, use the complete destructor name. This is relevant if a
        // class with a destructor is declared within a destructor.
        mangleCXXDtorType(Dtor_Complete);
      break;
      
    case DeclarationName::CXXConversionFunctionName:
      // <operator-name> ::= ?B # (cast)
      // The target type is encoded as the return type.
      Out << "?B";
      break;
      
    case DeclarationName::CXXOperatorName:
      mangleOperatorName(Name.getCXXOverloadedOperator(), ND->getLocation());
      break;
      
    case DeclarationName::CXXLiteralOperatorName: {
      // FIXME: Was this added in VS2010? Does MS even know how to mangle this?
      DiagnosticsEngine Diags = Context.getDiags();
      unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
        "cannot mangle this literal operator yet");
      Diags.Report(ND->getLocation(), DiagID);
      break;
    }
      
    case DeclarationName::CXXUsingDirective:
      llvm_unreachable("Can't mangle a using directive name!");
  }
}

void MicrosoftCXXNameMangler::manglePostfix(const DeclContext *DC,
                                            bool NoFunction) {
  // <postfix> ::= <unqualified-name> [<postfix>]
  //           ::= <substitution> [<postfix>]

  if (!DC) return;

  while (isa<LinkageSpecDecl>(DC))
    DC = DC->getParent();

  if (DC->isTranslationUnit())
    return;

  if (const BlockDecl *BD = dyn_cast<BlockDecl>(DC)) {
    Context.mangleBlock(BD, Out);
    Out << '@';
    return manglePostfix(DC->getParent(), NoFunction);
  } else if (isa<CapturedDecl>(DC)) {
    // Skip CapturedDecl context.
    manglePostfix(DC->getParent(), NoFunction);
    return;
  }

  if (NoFunction && (isa<FunctionDecl>(DC) || isa<ObjCMethodDecl>(DC)))
    return;
  else if (const ObjCMethodDecl *Method = dyn_cast<ObjCMethodDecl>(DC))
    mangleObjCMethodName(Method);
  else if (const FunctionDecl *Func = dyn_cast<FunctionDecl>(DC))
    mangleLocalName(Func);
  else {
    mangleUnqualifiedName(cast<NamedDecl>(DC));
    manglePostfix(DC->getParent(), NoFunction);
  }
}

void MicrosoftCXXNameMangler::mangleCXXDtorType(CXXDtorType T) {
  switch (T) {
  case Dtor_Deleting:
    Out << "?_G";
    return;
  case Dtor_Base:
    // FIXME: We should be asked to mangle base dtors.
    // However, fixing this would require larger changes to the CodeGenModule.
    // Please put llvm_unreachable here when CGM is changed.
    // For now, just mangle a base dtor the same way as a complete dtor...
  case Dtor_Complete:
    Out << "?1";
    return;
  }
  llvm_unreachable("Unsupported dtor type?");
}

void MicrosoftCXXNameMangler::mangleOperatorName(OverloadedOperatorKind OO,
                                                 SourceLocation Loc) {
  switch (OO) {
  //                     ?0 # constructor
  //                     ?1 # destructor
  // <operator-name> ::= ?2 # new
  case OO_New: Out << "?2"; break;
  // <operator-name> ::= ?3 # delete
  case OO_Delete: Out << "?3"; break;
  // <operator-name> ::= ?4 # =
  case OO_Equal: Out << "?4"; break;
  // <operator-name> ::= ?5 # >>
  case OO_GreaterGreater: Out << "?5"; break;
  // <operator-name> ::= ?6 # <<
  case OO_LessLess: Out << "?6"; break;
  // <operator-name> ::= ?7 # !
  case OO_Exclaim: Out << "?7"; break;
  // <operator-name> ::= ?8 # ==
  case OO_EqualEqual: Out << "?8"; break;
  // <operator-name> ::= ?9 # !=
  case OO_ExclaimEqual: Out << "?9"; break;
  // <operator-name> ::= ?A # []
  case OO_Subscript: Out << "?A"; break;
  //                     ?B # conversion
  // <operator-name> ::= ?C # ->
  case OO_Arrow: Out << "?C"; break;
  // <operator-name> ::= ?D # *
  case OO_Star: Out << "?D"; break;
  // <operator-name> ::= ?E # ++
  case OO_PlusPlus: Out << "?E"; break;
  // <operator-name> ::= ?F # --
  case OO_MinusMinus: Out << "?F"; break;
  // <operator-name> ::= ?G # -
  case OO_Minus: Out << "?G"; break;
  // <operator-name> ::= ?H # +
  case OO_Plus: Out << "?H"; break;
  // <operator-name> ::= ?I # &
  case OO_Amp: Out << "?I"; break;
  // <operator-name> ::= ?J # ->*
  case OO_ArrowStar: Out << "?J"; break;
  // <operator-name> ::= ?K # /
  case OO_Slash: Out << "?K"; break;
  // <operator-name> ::= ?L # %
  case OO_Percent: Out << "?L"; break;
  // <operator-name> ::= ?M # <
  case OO_Less: Out << "?M"; break;
  // <operator-name> ::= ?N # <=
  case OO_LessEqual: Out << "?N"; break;
  // <operator-name> ::= ?O # >
  case OO_Greater: Out << "?O"; break;
  // <operator-name> ::= ?P # >=
  case OO_GreaterEqual: Out << "?P"; break;
  // <operator-name> ::= ?Q # ,
  case OO_Comma: Out << "?Q"; break;
  // <operator-name> ::= ?R # ()
  case OO_Call: Out << "?R"; break;
  // <operator-name> ::= ?S # ~
  case OO_Tilde: Out << "?S"; break;
  // <operator-name> ::= ?T # ^
  case OO_Caret: Out << "?T"; break;
  // <operator-name> ::= ?U # |
  case OO_Pipe: Out << "?U"; break;
  // <operator-name> ::= ?V # &&
  case OO_AmpAmp: Out << "?V"; break;
  // <operator-name> ::= ?W # ||
  case OO_PipePipe: Out << "?W"; break;
  // <operator-name> ::= ?X # *=
  case OO_StarEqual: Out << "?X"; break;
  // <operator-name> ::= ?Y # +=
  case OO_PlusEqual: Out << "?Y"; break;
  // <operator-name> ::= ?Z # -=
  case OO_MinusEqual: Out << "?Z"; break;
  // <operator-name> ::= ?_0 # /=
  case OO_SlashEqual: Out << "?_0"; break;
  // <operator-name> ::= ?_1 # %=
  case OO_PercentEqual: Out << "?_1"; break;
  // <operator-name> ::= ?_2 # >>=
  case OO_GreaterGreaterEqual: Out << "?_2"; break;
  // <operator-name> ::= ?_3 # <<=
  case OO_LessLessEqual: Out << "?_3"; break;
  // <operator-name> ::= ?_4 # &=
  case OO_AmpEqual: Out << "?_4"; break;
  // <operator-name> ::= ?_5 # |=
  case OO_PipeEqual: Out << "?_5"; break;
  // <operator-name> ::= ?_6 # ^=
  case OO_CaretEqual: Out << "?_6"; break;
  //                     ?_7 # vftable
  //                     ?_8 # vbtable
  //                     ?_9 # vcall
  //                     ?_A # typeof
  //                     ?_B # local static guard
  //                     ?_C # string
  //                     ?_D # vbase destructor
  //                     ?_E # vector deleting destructor
  //                     ?_F # default constructor closure
  //                     ?_G # scalar deleting destructor
  //                     ?_H # vector constructor iterator
  //                     ?_I # vector destructor iterator
  //                     ?_J # vector vbase constructor iterator
  //                     ?_K # virtual displacement map
  //                     ?_L # eh vector constructor iterator
  //                     ?_M # eh vector destructor iterator
  //                     ?_N # eh vector vbase constructor iterator
  //                     ?_O # copy constructor closure
  //                     ?_P<name> # udt returning <name>
  //                     ?_Q # <unknown>
  //                     ?_R0 # RTTI Type Descriptor
  //                     ?_R1 # RTTI Base Class Descriptor at (a,b,c,d)
  //                     ?_R2 # RTTI Base Class Array
  //                     ?_R3 # RTTI Class Hierarchy Descriptor
  //                     ?_R4 # RTTI Complete Object Locator
  //                     ?_S # local vftable
  //                     ?_T # local vftable constructor closure
  // <operator-name> ::= ?_U # new[]
  case OO_Array_New: Out << "?_U"; break;
  // <operator-name> ::= ?_V # delete[]
  case OO_Array_Delete: Out << "?_V"; break;
    
  case OO_Conditional: {
    DiagnosticsEngine &Diags = Context.getDiags();
    unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
      "cannot mangle this conditional operator yet");
    Diags.Report(Loc, DiagID);
    break;
  }
    
  case OO_None:
  case NUM_OVERLOADED_OPERATORS:
    llvm_unreachable("Not an overloaded operator");
  }
}

void MicrosoftCXXNameMangler::mangleSourceName(const IdentifierInfo *II) {
  // <source name> ::= <identifier> @
  std::string key = II->getNameStart();
  BackRefMap::iterator Found;
  if (UseNameBackReferences)
    Found = NameBackReferences.find(key);
  if (!UseNameBackReferences || Found == NameBackReferences.end()) {
    Out << II->getName() << '@';
    if (UseNameBackReferences && NameBackReferences.size() < 10) {
      size_t Size = NameBackReferences.size();
      NameBackReferences[key] = Size;
    }
  } else {
    Out << Found->second;
  }
}

void MicrosoftCXXNameMangler::mangleObjCMethodName(const ObjCMethodDecl *MD) {
  Context.mangleObjCMethodName(MD, Out);
}

// Find out how many function decls live above this one and return an integer
// suitable for use as the number in a numbered anonymous scope.
// TODO: Memoize.
static unsigned getLocalNestingLevel(const FunctionDecl *FD) {
  const DeclContext *DC = FD->getParent();
  int level = 1;

  while (DC && !DC->isTranslationUnit()) {
    if (isa<FunctionDecl>(DC) || isa<ObjCMethodDecl>(DC)) level++;
    DC = DC->getParent();
  }

  return 2*level;
}

void MicrosoftCXXNameMangler::mangleLocalName(const FunctionDecl *FD) {
  // <nested-name> ::= <numbered-anonymous-scope> ? <mangled-name>
  // <numbered-anonymous-scope> ::= ? <number>
  // Even though the name is rendered in reverse order (e.g.
  // A::B::C is rendered as C@B@A), VC numbers the scopes from outermost to
  // innermost. So a method bar in class C local to function foo gets mangled
  // as something like:
  // ?bar@C@?1??foo@@YAXXZ@QAEXXZ
  // This is more apparent when you have a type nested inside a method of a
  // type nested inside a function. A method baz in class D local to method
  // bar of class C local to function foo gets mangled as:
  // ?baz@D@?3??bar@C@?1??foo@@YAXXZ@QAEXXZ@QAEXXZ
  // This scheme is general enough to support GCC-style nested
  // functions. You could have a method baz of class C inside a function bar
  // inside a function foo, like so:
  // ?baz@C@?3??bar@?1??foo@@YAXXZ@YAXXZ@QAEXXZ
  int NestLevel = getLocalNestingLevel(FD);
  Out << '?';
  mangleNumber(NestLevel);
  Out << '?';
  mangle(FD, "?");
}

void MicrosoftCXXNameMangler::mangleTemplateInstantiationName(
                                                         const TemplateDecl *TD,
                     const TemplateArgumentList &TemplateArgs) {
  // <template-name> ::= <unscoped-template-name> <template-args>
  //                 ::= <substitution>
  // Always start with the unqualified name.

  // Templates have their own context for back references.
  ArgBackRefMap OuterArgsContext;
  BackRefMap OuterTemplateContext;
  NameBackReferences.swap(OuterTemplateContext);
  TypeBackReferences.swap(OuterArgsContext);

  mangleUnscopedTemplateName(TD);
  mangleTemplateArgs(TD, TemplateArgs);

  // Restore the previous back reference contexts.
  NameBackReferences.swap(OuterTemplateContext);
  TypeBackReferences.swap(OuterArgsContext);
}

void
MicrosoftCXXNameMangler::mangleUnscopedTemplateName(const TemplateDecl *TD) {
  // <unscoped-template-name> ::= ?$ <unqualified-name>
  Out << "?$";
  mangleUnqualifiedName(TD);
}

void
MicrosoftCXXNameMangler::mangleIntegerLiteral(const llvm::APSInt &Value,
                                              bool IsBoolean) {
  // <integer-literal> ::= $0 <number>
  Out << "$0";
  // Make sure booleans are encoded as 0/1.
  if (IsBoolean && Value.getBoolValue())
    mangleNumber(1);
  else
    mangleNumber(Value);
}

void
MicrosoftCXXNameMangler::mangleExpression(const Expr *E) {
  // See if this is a constant expression.
  llvm::APSInt Value;
  if (E->isIntegerConstantExpr(Value, Context.getASTContext())) {
    mangleIntegerLiteral(Value, E->getType()->isBooleanType());
    return;
  }

  // As bad as this diagnostic is, it's better than crashing.
  DiagnosticsEngine &Diags = Context.getDiags();
  unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
                                   "cannot yet mangle expression type %0");
  Diags.Report(E->getExprLoc(), DiagID)
    << E->getStmtClassName() << E->getSourceRange();
}

void
MicrosoftCXXNameMangler::mangleTemplateArgs(const TemplateDecl *TD,
                                     const TemplateArgumentList &TemplateArgs) {
  // <template-args> ::= {<type> | <integer-literal>}+ @
  unsigned NumTemplateArgs = TemplateArgs.size();
  for (unsigned i = 0; i < NumTemplateArgs; ++i) {
    const TemplateArgument &TA = TemplateArgs[i];
    switch (TA.getKind()) {
    case TemplateArgument::Null:
      llvm_unreachable("Can't mangle null template arguments!");
    case TemplateArgument::Type: {
      QualType T = TA.getAsType();
      mangleType(T, SourceRange(), QMM_Escape);
      break;
    }
    case TemplateArgument::Declaration:
      mangle(cast<NamedDecl>(TA.getAsDecl()), "$1?");
      break;
    case TemplateArgument::Integral:
      mangleIntegerLiteral(TA.getAsIntegral(),
                           TA.getIntegralType()->isBooleanType());
      break;
    case TemplateArgument::Expression:
      mangleExpression(TA.getAsExpr());
      break;
    case TemplateArgument::Template:
    case TemplateArgument::TemplateExpansion:
    case TemplateArgument::NullPtr:
    case TemplateArgument::Pack: {
      // Issue a diagnostic.
      DiagnosticsEngine &Diags = Context.getDiags();
      unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
        "cannot mangle template argument %0 of kind %select{ERROR|ERROR|"
        "pointer/reference|nullptr|integral|template|template pack expansion|"
        "ERROR|parameter pack}1 yet");
      Diags.Report(TD->getLocation(), DiagID)
        << i + 1
        << TA.getKind()
        << TD->getSourceRange();
    }
    }
  }
  Out << '@';
}

void MicrosoftCXXNameMangler::mangleQualifiers(Qualifiers Quals,
                                               bool IsMember) {
  // <cvr-qualifiers> ::= [E] [F] [I] <base-cvr-qualifiers>
  // 'E' means __ptr64 (32-bit only); 'F' means __unaligned (32/64-bit only);
  // 'I' means __restrict (32/64-bit).
  // Note that the MSVC __restrict keyword isn't the same as the C99 restrict
  // keyword!
  // <base-cvr-qualifiers> ::= A  # near
  //                       ::= B  # near const
  //                       ::= C  # near volatile
  //                       ::= D  # near const volatile
  //                       ::= E  # far (16-bit)
  //                       ::= F  # far const (16-bit)
  //                       ::= G  # far volatile (16-bit)
  //                       ::= H  # far const volatile (16-bit)
  //                       ::= I  # huge (16-bit)
  //                       ::= J  # huge const (16-bit)
  //                       ::= K  # huge volatile (16-bit)
  //                       ::= L  # huge const volatile (16-bit)
  //                       ::= M <basis> # based
  //                       ::= N <basis> # based const
  //                       ::= O <basis> # based volatile
  //                       ::= P <basis> # based const volatile
  //                       ::= Q  # near member
  //                       ::= R  # near const member
  //                       ::= S  # near volatile member
  //                       ::= T  # near const volatile member
  //                       ::= U  # far member (16-bit)
  //                       ::= V  # far const member (16-bit)
  //                       ::= W  # far volatile member (16-bit)
  //                       ::= X  # far const volatile member (16-bit)
  //                       ::= Y  # huge member (16-bit)
  //                       ::= Z  # huge const member (16-bit)
  //                       ::= 0  # huge volatile member (16-bit)
  //                       ::= 1  # huge const volatile member (16-bit)
  //                       ::= 2 <basis> # based member
  //                       ::= 3 <basis> # based const member
  //                       ::= 4 <basis> # based volatile member
  //                       ::= 5 <basis> # based const volatile member
  //                       ::= 6  # near function (pointers only)
  //                       ::= 7  # far function (pointers only)
  //                       ::= 8  # near method (pointers only)
  //                       ::= 9  # far method (pointers only)
  //                       ::= _A <basis> # based function (pointers only)
  //                       ::= _B <basis> # based function (far?) (pointers only)
  //                       ::= _C <basis> # based method (pointers only)
  //                       ::= _D <basis> # based method (far?) (pointers only)
  //                       ::= _E # block (Clang)
  // <basis> ::= 0 # __based(void)
  //         ::= 1 # __based(segment)?
  //         ::= 2 <name> # __based(name)
  //         ::= 3 # ?
  //         ::= 4 # ?
  //         ::= 5 # not really based
  bool HasConst = Quals.hasConst(),
       HasVolatile = Quals.hasVolatile();
  if (!IsMember) {
    if (HasConst && HasVolatile) {
      Out << 'D';
    } else if (HasVolatile) {
      Out << 'C';
    } else if (HasConst) {
      Out << 'B';
    } else {
      Out << 'A';
    }
  } else {
    if (HasConst && HasVolatile) {
      Out << 'T';
    } else if (HasVolatile) {
      Out << 'S';
    } else if (HasConst) {
      Out << 'R';
    } else {
      Out << 'Q';
    }
  }

  // FIXME: For now, just drop all extension qualifiers on the floor.
}

void MicrosoftCXXNameMangler::manglePointerQualifiers(Qualifiers Quals) {
  // <pointer-cvr-qualifiers> ::= P  # no qualifiers
  //                          ::= Q  # const
  //                          ::= R  # volatile
  //                          ::= S  # const volatile
  bool HasConst = Quals.hasConst(),
       HasVolatile = Quals.hasVolatile();
  if (HasConst && HasVolatile) {
    Out << 'S';
  } else if (HasVolatile) {
    Out << 'R';
  } else if (HasConst) {
    Out << 'Q';
  } else {
    Out << 'P';
  }
}

void MicrosoftCXXNameMangler::mangleArgumentType(QualType T,
                                                 SourceRange Range) {
  void *TypePtr = getASTContext().getCanonicalType(T).getAsOpaquePtr();
  ArgBackRefMap::iterator Found = TypeBackReferences.find(TypePtr);

  if (Found == TypeBackReferences.end()) {
    size_t OutSizeBefore = Out.GetNumBytesInBuffer();

    if (const ArrayType *AT = getASTContext().getAsArrayType(T)) {
      mangleDecayedArrayType(AT, false);
    } else if (const FunctionType *FT = T->getAs<FunctionType>()) {
      Out << "P6";
      mangleFunctionType(FT, 0, false, false);
    } else {
      mangleType(T, Range, QMM_Drop);
    }

    // See if it's worth creating a back reference.
    // Only types longer than 1 character are considered
    // and only 10 back references slots are available:
    bool LongerThanOneChar = (Out.GetNumBytesInBuffer() - OutSizeBefore > 1);
    if (LongerThanOneChar && TypeBackReferences.size() < 10) {
      size_t Size = TypeBackReferences.size();
      TypeBackReferences[TypePtr] = Size;
    }
  } else {
    Out << Found->second;
  }
}

void MicrosoftCXXNameMangler::mangleType(QualType T, SourceRange Range,
                                         QualifierMangleMode QMM) {
  // Only operate on the canonical type!
  T = getASTContext().getCanonicalType(T);
  Qualifiers Quals = T.getLocalQualifiers();

  if (const ArrayType *AT = dyn_cast<ArrayType>(T)) {
    if (QMM == QMM_Mangle)
      Out << 'A';
    else if (QMM == QMM_Escape || QMM == QMM_Result)
      Out << "$$B";
    mangleArrayType(AT, Quals);
    return;
  }

  bool IsPointer = T->isAnyPointerType() || T->isMemberPointerType() ||
                   T->isBlockPointerType();

  switch (QMM) {
  case QMM_Drop:
    break;
  case QMM_Mangle:
    if (const FunctionType *FT = dyn_cast<FunctionType>(T)) {
      Out << '6';
      mangleFunctionType(FT, 0, false, false);
      return;
    }
    mangleQualifiers(Quals, false);
    break;
  case QMM_Escape:
    if (!IsPointer && Quals) {
      Out << "$$C";
      mangleQualifiers(Quals, false);
    }
    break;
  case QMM_Result:
    if ((!IsPointer && Quals) || isa<TagType>(T)) {
      Out << '?';
      mangleQualifiers(Quals, false);
    }
    break;
  }

  // We have to mangle these now, while we still have enough information.
  if (IsPointer)
    manglePointerQualifiers(Quals);
  const Type *ty = T.getTypePtr();

  switch (ty->getTypeClass()) {
#define ABSTRACT_TYPE(CLASS, PARENT)
#define NON_CANONICAL_TYPE(CLASS, PARENT) \
  case Type::CLASS: \
    llvm_unreachable("can't mangle non-canonical type " #CLASS "Type"); \
    return;
#define TYPE(CLASS, PARENT) \
  case Type::CLASS: \
    mangleType(cast<CLASS##Type>(ty), Range); \
    break;
#include "clang/AST/TypeNodes.def"
#undef ABSTRACT_TYPE
#undef NON_CANONICAL_TYPE
#undef TYPE
  }
}

void MicrosoftCXXNameMangler::mangleType(const BuiltinType *T,
                                         SourceRange Range) {
  //  <type>         ::= <builtin-type>
  //  <builtin-type> ::= X  # void
  //                 ::= C  # signed char
  //                 ::= D  # char
  //                 ::= E  # unsigned char
  //                 ::= F  # short
  //                 ::= G  # unsigned short (or wchar_t if it's not a builtin)
  //                 ::= H  # int
  //                 ::= I  # unsigned int
  //                 ::= J  # long
  //                 ::= K  # unsigned long
  //                     L  # <none>
  //                 ::= M  # float
  //                 ::= N  # double
  //                 ::= O  # long double (__float80 is mangled differently)
  //                 ::= _J # long long, __int64
  //                 ::= _K # unsigned long long, __int64
  //                 ::= _L # __int128
  //                 ::= _M # unsigned __int128
  //                 ::= _N # bool
  //                     _O # <array in parameter>
  //                 ::= _T # __float80 (Intel)
  //                 ::= _W # wchar_t
  //                 ::= _Z # __float80 (Digital Mars)
  switch (T->getKind()) {
  case BuiltinType::Void: Out << 'X'; break;
  case BuiltinType::SChar: Out << 'C'; break;
  case BuiltinType::Char_U: case BuiltinType::Char_S: Out << 'D'; break;
  case BuiltinType::UChar: Out << 'E'; break;
  case BuiltinType::Short: Out << 'F'; break;
  case BuiltinType::UShort: Out << 'G'; break;
  case BuiltinType::Int: Out << 'H'; break;
  case BuiltinType::UInt: Out << 'I'; break;
  case BuiltinType::Long: Out << 'J'; break;
  case BuiltinType::ULong: Out << 'K'; break;
  case BuiltinType::Float: Out << 'M'; break;
  case BuiltinType::Double: Out << 'N'; break;
  // TODO: Determine size and mangle accordingly
  case BuiltinType::LongDouble: Out << 'O'; break;
  case BuiltinType::LongLong: Out << "_J"; break;
  case BuiltinType::ULongLong: Out << "_K"; break;
  case BuiltinType::Int128: Out << "_L"; break;
  case BuiltinType::UInt128: Out << "_M"; break;
  case BuiltinType::Bool: Out << "_N"; break;
  case BuiltinType::WChar_S:
  case BuiltinType::WChar_U: Out << "_W"; break;

#define BUILTIN_TYPE(Id, SingletonId)
#define PLACEHOLDER_TYPE(Id, SingletonId) \
  case BuiltinType::Id:
#include "clang/AST/BuiltinTypes.def"
  case BuiltinType::Dependent:
    llvm_unreachable("placeholder types shouldn't get to name mangling");

  case BuiltinType::ObjCId: Out << "PAUobjc_object@@"; break;
  case BuiltinType::ObjCClass: Out << "PAUobjc_class@@"; break;
  case BuiltinType::ObjCSel: Out << "PAUobjc_selector@@"; break;

  case BuiltinType::OCLImage1d: Out << "PAUocl_image1d@@"; break;
  case BuiltinType::OCLImage1dArray: Out << "PAUocl_image1darray@@"; break;
  case BuiltinType::OCLImage1dBuffer: Out << "PAUocl_image1dbuffer@@"; break;
  case BuiltinType::OCLImage2d: Out << "PAUocl_image2d@@"; break;
  case BuiltinType::OCLImage2dArray: Out << "PAUocl_image2darray@@"; break;
  case BuiltinType::OCLImage3d: Out << "PAUocl_image3d@@"; break;
  case BuiltinType::OCLSampler: Out << "PAUocl_sampler@@"; break;
  case BuiltinType::OCLEvent: Out << "PAUocl_event@@"; break;
 
  case BuiltinType::NullPtr: Out << "$$T"; break;

  case BuiltinType::Char16:
  case BuiltinType::Char32:
  case BuiltinType::Half: {
    DiagnosticsEngine &Diags = Context.getDiags();
    unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
      "cannot mangle this built-in %0 type yet");
    Diags.Report(Range.getBegin(), DiagID)
      << T->getName(Context.getASTContext().getPrintingPolicy())
      << Range;
    break;
  }
  }
}

// <type>          ::= <function-type>
void MicrosoftCXXNameMangler::mangleType(const FunctionProtoType *T,
                                         SourceRange) {
  // Structors only appear in decls, so at this point we know it's not a
  // structor type.
  // FIXME: This may not be lambda-friendly.
  Out << "$$A6";
  mangleFunctionType(T, NULL, false, false);
}
void MicrosoftCXXNameMangler::mangleType(const FunctionNoProtoType *T,
                                         SourceRange) {
  llvm_unreachable("Can't mangle K&R function prototypes");
}

void MicrosoftCXXNameMangler::mangleFunctionType(const FunctionType *T,
                                                 const FunctionDecl *D,
                                                 bool IsStructor,
                                                 bool IsInstMethod) {
  // <function-type> ::= <this-cvr-qualifiers> <calling-convention>
  //                     <return-type> <argument-list> <throw-spec>
  const FunctionProtoType *Proto = cast<FunctionProtoType>(T);

  // If this is a C++ instance method, mangle the CVR qualifiers for the
  // this pointer.
  if (IsInstMethod)
    mangleQualifiers(Qualifiers::fromCVRMask(Proto->getTypeQuals()), false);

  mangleCallingConvention(T, IsInstMethod);

  // <return-type> ::= <type>
  //               ::= @ # structors (they have no declared return type)
  if (IsStructor) {
    if (isa<CXXDestructorDecl>(D) && D == Structor &&
        StructorType == Dtor_Deleting) {
      // The scalar deleting destructor takes an extra int argument.
      // However, the FunctionType generated has 0 arguments.
      // FIXME: This is a temporary hack.
      // Maybe should fix the FunctionType creation instead?
      Out << "PAXI@Z";
      return;
    }
    Out << '@';
  } else {
    mangleType(Proto->getResultType(), SourceRange(), QMM_Result);
  }

  // <argument-list> ::= X # void
  //                 ::= <type>+ @
  //                 ::= <type>* Z # varargs
  if (Proto->getNumArgs() == 0 && !Proto->isVariadic()) {
    Out << 'X';
  } else {
    if (D) {
      // If we got a decl, use the type-as-written to make sure arrays
      // get mangled right.  Note that we can't rely on the TSI
      // existing if (for example) the parameter was synthesized.
      for (FunctionDecl::param_const_iterator Parm = D->param_begin(),
             ParmEnd = D->param_end(); Parm != ParmEnd; ++Parm) {
        TypeSourceInfo *TSI = (*Parm)->getTypeSourceInfo();
        QualType Type = TSI ? TSI->getType() : (*Parm)->getType();
        mangleArgumentType(Type, (*Parm)->getSourceRange());
      }
    } else {
      // Happens for function pointer type arguments for example.
      for (FunctionProtoType::arg_type_iterator Arg = Proto->arg_type_begin(),
           ArgEnd = Proto->arg_type_end();
           Arg != ArgEnd; ++Arg)
        mangleArgumentType(*Arg, SourceRange());
    }
    // <builtin-type>      ::= Z  # ellipsis
    if (Proto->isVariadic())
      Out << 'Z';
    else
      Out << '@';
  }

  mangleThrowSpecification(Proto);
}

void MicrosoftCXXNameMangler::mangleFunctionClass(const FunctionDecl *FD) {
  // <function-class>  ::= <member-function> E? # E designates a 64-bit 'this'
  //                                            # pointer. in 64-bit mode *all*
  //                                            # 'this' pointers are 64-bit.
  //                   ::= <global-function>
  // <member-function> ::= A # private: near
  //                   ::= B # private: far
  //                   ::= C # private: static near
  //                   ::= D # private: static far
  //                   ::= E # private: virtual near
  //                   ::= F # private: virtual far
  //                   ::= G # private: thunk near
  //                   ::= H # private: thunk far
  //                   ::= I # protected: near
  //                   ::= J # protected: far
  //                   ::= K # protected: static near
  //                   ::= L # protected: static far
  //                   ::= M # protected: virtual near
  //                   ::= N # protected: virtual far
  //                   ::= O # protected: thunk near
  //                   ::= P # protected: thunk far
  //                   ::= Q # public: near
  //                   ::= R # public: far
  //                   ::= S # public: static near
  //                   ::= T # public: static far
  //                   ::= U # public: virtual near
  //                   ::= V # public: virtual far
  //                   ::= W # public: thunk near
  //                   ::= X # public: thunk far
  // <global-function> ::= Y # global near
  //                   ::= Z # global far
  if (const CXXMethodDecl *MD = dyn_cast<CXXMethodDecl>(FD)) {
    switch (MD->getAccess()) {
      default:
      case AS_private:
        if (MD->isStatic())
          Out << 'C';
        else if (MD->isVirtual())
          Out << 'E';
        else
          Out << 'A';
        break;
      case AS_protected:
        if (MD->isStatic())
          Out << 'K';
        else if (MD->isVirtual())
          Out << 'M';
        else
          Out << 'I';
        break;
      case AS_public:
        if (MD->isStatic())
          Out << 'S';
        else if (MD->isVirtual())
          Out << 'U';
        else
          Out << 'Q';
    }
    if (PointersAre64Bit && !MD->isStatic())
      Out << 'E';
  } else
    Out << 'Y';
}
void MicrosoftCXXNameMangler::mangleCallingConvention(const FunctionType *T,
                                                      bool IsInstMethod) {
  // <calling-convention> ::= A # __cdecl
  //                      ::= B # __export __cdecl
  //                      ::= C # __pascal
  //                      ::= D # __export __pascal
  //                      ::= E # __thiscall
  //                      ::= F # __export __thiscall
  //                      ::= G # __stdcall
  //                      ::= H # __export __stdcall
  //                      ::= I # __fastcall
  //                      ::= J # __export __fastcall
  // The 'export' calling conventions are from a bygone era
  // (*cough*Win16*cough*) when functions were declared for export with
  // that keyword. (It didn't actually export them, it just made them so
  // that they could be in a DLL and somebody from another module could call
  // them.)
  CallingConv CC = T->getCallConv();
  if (CC == CC_Default) {
    if (IsInstMethod) {
      const FunctionProtoType *FPT =
        T->getCanonicalTypeUnqualified().castAs<FunctionProtoType>();
      bool isVariadic = FPT->isVariadic();
      CC = getASTContext().getDefaultCXXMethodCallConv(isVariadic);
    } else {
      CC = CC_C;
    }
  }
  switch (CC) {
    default:
      llvm_unreachable("Unsupported CC for mangling");
    case CC_Default:
    case CC_C: Out << 'A'; break;
    case CC_X86Pascal: Out << 'C'; break;
    case CC_X86ThisCall: Out << 'E'; break;
    case CC_X86StdCall: Out << 'G'; break;
    case CC_X86FastCall: Out << 'I'; break;
  }
}
void MicrosoftCXXNameMangler::mangleThrowSpecification(
                                                const FunctionProtoType *FT) {
  // <throw-spec> ::= Z # throw(...) (default)
  //              ::= @ # throw() or __declspec/__attribute__((nothrow))
  //              ::= <type>+
  // NOTE: Since the Microsoft compiler ignores throw specifications, they are
  // all actually mangled as 'Z'. (They're ignored because their associated
  // functionality isn't implemented, and probably never will be.)
  Out << 'Z';
}

void MicrosoftCXXNameMangler::mangleType(const UnresolvedUsingType *T,
                                         SourceRange Range) {
  // Probably should be mangled as a template instantiation; need to see what
  // VC does first.
  DiagnosticsEngine &Diags = Context.getDiags();
  unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
    "cannot mangle this unresolved dependent type yet");
  Diags.Report(Range.getBegin(), DiagID)
    << Range;
}

// <type>        ::= <union-type> | <struct-type> | <class-type> | <enum-type>
// <union-type>  ::= T <name>
// <struct-type> ::= U <name>
// <class-type>  ::= V <name>
// <enum-type>   ::= W <size> <name>
void MicrosoftCXXNameMangler::mangleType(const EnumType *T, SourceRange) {
  mangleType(cast<TagType>(T));
}
void MicrosoftCXXNameMangler::mangleType(const RecordType *T, SourceRange) {
  mangleType(cast<TagType>(T));
}
void MicrosoftCXXNameMangler::mangleType(const TagType *T) {
  switch (T->getDecl()->getTagKind()) {
    case TTK_Union:
      Out << 'T';
      break;
    case TTK_Struct:
    case TTK_Interface:
      Out << 'U';
      break;
    case TTK_Class:
      Out << 'V';
      break;
    case TTK_Enum:
      Out << 'W';
      Out << getASTContext().getTypeSizeInChars(
                cast<EnumDecl>(T->getDecl())->getIntegerType()).getQuantity();
      break;
  }
  mangleName(T->getDecl());
}

// <type>       ::= <array-type>
// <array-type> ::= <pointer-cvr-qualifiers> <cvr-qualifiers>
//                  [Y <dimension-count> <dimension>+]
//                  <element-type> # as global, E is never required
//              ::= Q E? <cvr-qualifiers> [Y <dimension-count> <dimension>+]
//                  <element-type> # as param, E is required for 64-bit
// It's supposed to be the other way around, but for some strange reason, it
// isn't. Today this behavior is retained for the sole purpose of backwards
// compatibility.
void MicrosoftCXXNameMangler::mangleDecayedArrayType(const ArrayType *T,
                                                     bool IsGlobal) {
  // This isn't a recursive mangling, so now we have to do it all in this
  // one call.
  if (IsGlobal) {
    manglePointerQualifiers(T->getElementType().getQualifiers());
  } else {
    Out << 'Q';
    if (PointersAre64Bit)
      Out << 'E';
  }
  mangleType(T->getElementType(), SourceRange());
}
void MicrosoftCXXNameMangler::mangleType(const ConstantArrayType *T,
                                         SourceRange) {
  llvm_unreachable("Should have been special cased");
}
void MicrosoftCXXNameMangler::mangleType(const VariableArrayType *T,
                                         SourceRange) {
  llvm_unreachable("Should have been special cased");
}
void MicrosoftCXXNameMangler::mangleType(const DependentSizedArrayType *T,
                                         SourceRange) {
  llvm_unreachable("Should have been special cased");
}
void MicrosoftCXXNameMangler::mangleType(const IncompleteArrayType *T,
                                         SourceRange) {
  llvm_unreachable("Should have been special cased");
}
void MicrosoftCXXNameMangler::mangleArrayType(const ArrayType *T,
                                              Qualifiers Quals) {
  QualType ElementTy(T, 0);
  SmallVector<llvm::APInt, 3> Dimensions;
  for (;;) {
    if (const ConstantArrayType *CAT =
          getASTContext().getAsConstantArrayType(ElementTy)) {
      Dimensions.push_back(CAT->getSize());
      ElementTy = CAT->getElementType();
    } else if (ElementTy->isVariableArrayType()) {
      const VariableArrayType *VAT =
        getASTContext().getAsVariableArrayType(ElementTy);
      DiagnosticsEngine &Diags = Context.getDiags();
      unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
        "cannot mangle this variable-length array yet");
      Diags.Report(VAT->getSizeExpr()->getExprLoc(), DiagID)
        << VAT->getBracketsRange();
      return;
    } else if (ElementTy->isDependentSizedArrayType()) {
      // The dependent expression has to be folded into a constant (TODO).
      const DependentSizedArrayType *DSAT =
        getASTContext().getAsDependentSizedArrayType(ElementTy);
      DiagnosticsEngine &Diags = Context.getDiags();
      unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
        "cannot mangle this dependent-length array yet");
      Diags.Report(DSAT->getSizeExpr()->getExprLoc(), DiagID)
        << DSAT->getBracketsRange();
      return;
    } else if (const IncompleteArrayType *IAT =
          getASTContext().getAsIncompleteArrayType(ElementTy)) {
      Dimensions.push_back(llvm::APInt(32, 0));
      ElementTy = IAT->getElementType();
    }
    else break;
  }
  Out << 'Y';
  // <dimension-count> ::= <number> # number of extra dimensions
  mangleNumber(Dimensions.size());
  for (unsigned Dim = 0; Dim < Dimensions.size(); ++Dim)
    mangleNumber(Dimensions[Dim].getLimitedValue());
  mangleType(getASTContext().getQualifiedType(ElementTy.getTypePtr(), Quals),
             SourceRange(), QMM_Escape);
}

// <type>                   ::= <pointer-to-member-type>
// <pointer-to-member-type> ::= <pointer-cvr-qualifiers> <cvr-qualifiers>
//                                                          <class name> <type>
void MicrosoftCXXNameMangler::mangleType(const MemberPointerType *T,
                                         SourceRange Range) {
  QualType PointeeType = T->getPointeeType();
  if (const FunctionProtoType *FPT = PointeeType->getAs<FunctionProtoType>()) {
    Out << '8';
    mangleName(T->getClass()->castAs<RecordType>()->getDecl());
    mangleFunctionType(FPT, NULL, false, true);
  } else {
    mangleQualifiers(PointeeType.getQualifiers(), true);
    mangleName(T->getClass()->castAs<RecordType>()->getDecl());
    mangleType(PointeeType, Range, QMM_Drop);
  }
}

void MicrosoftCXXNameMangler::mangleType(const TemplateTypeParmType *T,
                                         SourceRange Range) {
  DiagnosticsEngine &Diags = Context.getDiags();
  unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
    "cannot mangle this template type parameter type yet");
  Diags.Report(Range.getBegin(), DiagID)
    << Range;
}

void MicrosoftCXXNameMangler::mangleType(
                                       const SubstTemplateTypeParmPackType *T,
                                       SourceRange Range) {
  DiagnosticsEngine &Diags = Context.getDiags();
  unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
    "cannot mangle this substituted parameter pack yet");
  Diags.Report(Range.getBegin(), DiagID)
    << Range;
}

// <type> ::= <pointer-type>
// <pointer-type> ::= E? <pointer-cvr-qualifiers> <cvr-qualifiers> <type>
//                       # the E is required for 64-bit non static pointers
void MicrosoftCXXNameMangler::mangleType(const PointerType *T,
                                         SourceRange Range) {
  QualType PointeeTy = T->getPointeeType();
  if (PointersAre64Bit && !T->getPointeeType()->isFunctionType())
    Out << 'E';
  mangleType(PointeeTy, Range);
}
void MicrosoftCXXNameMangler::mangleType(const ObjCObjectPointerType *T,
                                         SourceRange Range) {
  // Object pointers never have qualifiers.
  Out << 'A';
  mangleType(T->getPointeeType(), Range);
}

// <type> ::= <reference-type>
// <reference-type> ::= A E? <cvr-qualifiers> <type>
//                 # the E is required for 64-bit non static lvalue references
void MicrosoftCXXNameMangler::mangleType(const LValueReferenceType *T,
                                         SourceRange Range) {
  Out << 'A';
  if (PointersAre64Bit && !T->getPointeeType()->isFunctionType())
    Out << 'E';
  mangleType(T->getPointeeType(), Range);
}

// <type> ::= <r-value-reference-type>
// <r-value-reference-type> ::= $$Q E? <cvr-qualifiers> <type>
//                 # the E is required for 64-bit non static rvalue references
void MicrosoftCXXNameMangler::mangleType(const RValueReferenceType *T,
                                         SourceRange Range) {
  Out << "$$Q";
  if (PointersAre64Bit && !T->getPointeeType()->isFunctionType())
    Out << 'E';
  mangleType(T->getPointeeType(), Range);
}

void MicrosoftCXXNameMangler::mangleType(const ComplexType *T,
                                         SourceRange Range) {
  DiagnosticsEngine &Diags = Context.getDiags();
  unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
    "cannot mangle this complex number type yet");
  Diags.Report(Range.getBegin(), DiagID)
    << Range;
}

void MicrosoftCXXNameMangler::mangleType(const VectorType *T,
                                         SourceRange Range) {
  const BuiltinType *ET = T->getElementType()->getAs<BuiltinType>();
  assert(ET && "vectors with non-builtin elements are unsupported");
  uint64_t Width = getASTContext().getTypeSize(T);
  // Pattern match exactly the typedefs in our intrinsic headers.  Anything that
  // doesn't match the Intel types uses a custom mangling below.
  bool IntelVector = true;
  if (Width == 64 && ET->getKind() == BuiltinType::LongLong) {
    Out << "T__m64";
  } else if (Width == 128 || Width == 256) {
    if (ET->getKind() == BuiltinType::Float)
      Out << "T__m" << Width;
    else if (ET->getKind() == BuiltinType::LongLong)
      Out << "T__m" << Width << 'i';
    else if (ET->getKind() == BuiltinType::Double)
      Out << "U__m" << Width << 'd';
    else
      IntelVector = false;
  } else {
    IntelVector = false;
  }

  if (!IntelVector) {
    // The MS ABI doesn't have a special mangling for vector types, so we define
    // our own mangling to handle uses of __vector_size__ on user-specified
    // types, and for extensions like __v4sf.
    Out << "T__clang_vec" << T->getNumElements() << '_';
    mangleType(ET, Range);
  }

  Out << "@@";
}

void MicrosoftCXXNameMangler::mangleType(const ExtVectorType *T,
                                         SourceRange Range) {
  DiagnosticsEngine &Diags = Context.getDiags();
  unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
    "cannot mangle this extended vector type yet");
  Diags.Report(Range.getBegin(), DiagID)
    << Range;
}
void MicrosoftCXXNameMangler::mangleType(const DependentSizedExtVectorType *T,
                                         SourceRange Range) {
  DiagnosticsEngine &Diags = Context.getDiags();
  unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
    "cannot mangle this dependent-sized extended vector type yet");
  Diags.Report(Range.getBegin(), DiagID)
    << Range;
}

void MicrosoftCXXNameMangler::mangleType(const ObjCInterfaceType *T,
                                         SourceRange) {
  // ObjC interfaces have structs underlying them.
  Out << 'U';
  mangleName(T->getDecl());
}

void MicrosoftCXXNameMangler::mangleType(const ObjCObjectType *T,
                                         SourceRange Range) {
  // We don't allow overloading by different protocol qualification,
  // so mangling them isn't necessary.
  mangleType(T->getBaseType(), Range);
}

void MicrosoftCXXNameMangler::mangleType(const BlockPointerType *T,
                                         SourceRange Range) {
  Out << "_E";

  QualType pointee = T->getPointeeType();
  mangleFunctionType(pointee->castAs<FunctionProtoType>(), NULL, false, false);
}

void MicrosoftCXXNameMangler::mangleType(const InjectedClassNameType *T,
                                         SourceRange Range) {
  DiagnosticsEngine &Diags = Context.getDiags();
  unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
    "cannot mangle this injected class name type yet");
  Diags.Report(Range.getBegin(), DiagID)
    << Range;
}

void MicrosoftCXXNameMangler::mangleType(const TemplateSpecializationType *T,
                                         SourceRange Range) {
  DiagnosticsEngine &Diags = Context.getDiags();
  unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
    "cannot mangle this template specialization type yet");
  Diags.Report(Range.getBegin(), DiagID)
    << Range;
}

void MicrosoftCXXNameMangler::mangleType(const DependentNameType *T,
                                         SourceRange Range) {
  DiagnosticsEngine &Diags = Context.getDiags();
  unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
    "cannot mangle this dependent name type yet");
  Diags.Report(Range.getBegin(), DiagID)
    << Range;
}

void MicrosoftCXXNameMangler::mangleType(
                                 const DependentTemplateSpecializationType *T,
                                 SourceRange Range) {
  DiagnosticsEngine &Diags = Context.getDiags();
  unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
    "cannot mangle this dependent template specialization type yet");
  Diags.Report(Range.getBegin(), DiagID)
    << Range;
}

void MicrosoftCXXNameMangler::mangleType(const PackExpansionType *T,
                                         SourceRange Range) {
  DiagnosticsEngine &Diags = Context.getDiags();
  unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
    "cannot mangle this pack expansion yet");
  Diags.Report(Range.getBegin(), DiagID)
    << Range;
}

void MicrosoftCXXNameMangler::mangleType(const TypeOfType *T,
                                         SourceRange Range) {
  DiagnosticsEngine &Diags = Context.getDiags();
  unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
    "cannot mangle this typeof(type) yet");
  Diags.Report(Range.getBegin(), DiagID)
    << Range;
}

void MicrosoftCXXNameMangler::mangleType(const TypeOfExprType *T,
                                         SourceRange Range) {
  DiagnosticsEngine &Diags = Context.getDiags();
  unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
    "cannot mangle this typeof(expression) yet");
  Diags.Report(Range.getBegin(), DiagID)
    << Range;
}

void MicrosoftCXXNameMangler::mangleType(const DecltypeType *T,
                                         SourceRange Range) {
  DiagnosticsEngine &Diags = Context.getDiags();
  unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
    "cannot mangle this decltype() yet");
  Diags.Report(Range.getBegin(), DiagID)
    << Range;
}

void MicrosoftCXXNameMangler::mangleType(const UnaryTransformType *T,
                                         SourceRange Range) {
  DiagnosticsEngine &Diags = Context.getDiags();
  unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
    "cannot mangle this unary transform type yet");
  Diags.Report(Range.getBegin(), DiagID)
    << Range;
}

void MicrosoftCXXNameMangler::mangleType(const AutoType *T, SourceRange Range) {
  DiagnosticsEngine &Diags = Context.getDiags();
  unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
    "cannot mangle this 'auto' type yet");
  Diags.Report(Range.getBegin(), DiagID)
    << Range;
}

void MicrosoftCXXNameMangler::mangleType(const AtomicType *T,
                                         SourceRange Range) {
  DiagnosticsEngine &Diags = Context.getDiags();
  unsigned DiagID = Diags.getCustomDiagID(DiagnosticsEngine::Error,
    "cannot mangle this C11 atomic type yet");
  Diags.Report(Range.getBegin(), DiagID)
    << Range;
}

void MicrosoftMangleContext::mangleName(const NamedDecl *D,
                                        raw_ostream &Out) {
  assert((isa<FunctionDecl>(D) || isa<VarDecl>(D)) &&
         "Invalid mangleName() call, argument is not a variable or function!");
  assert(!isa<CXXConstructorDecl>(D) && !isa<CXXDestructorDecl>(D) &&
         "Invalid mangleName() call on 'structor decl!");

  PrettyStackTraceDecl CrashInfo(D, SourceLocation(),
                                 getASTContext().getSourceManager(),
                                 "Mangling declaration");

  MicrosoftCXXNameMangler Mangler(*this, Out);
  return Mangler.mangle(D);
}
void MicrosoftMangleContext::mangleThunk(const CXXMethodDecl *MD,
                                         const ThunkInfo &Thunk,
                                         raw_ostream &) {
  unsigned DiagID = getDiags().getCustomDiagID(DiagnosticsEngine::Error,
    "cannot mangle thunk for this method yet");
  getDiags().Report(MD->getLocation(), DiagID);
}
void MicrosoftMangleContext::mangleCXXDtorThunk(const CXXDestructorDecl *DD,
                                                CXXDtorType Type,
                                                const ThisAdjustment &,
                                                raw_ostream &) {
  unsigned DiagID = getDiags().getCustomDiagID(DiagnosticsEngine::Error,
    "cannot mangle thunk for this destructor yet");
  getDiags().Report(DD->getLocation(), DiagID);
}

void MicrosoftMangleContext::mangleCXXVTable(const CXXRecordDecl *RD,
                                             raw_ostream &Out) {
  // <mangled-name> ::= ?_7 <class-name> <storage-class>
  //                    <cvr-qualifiers> [<name>] @
  // NOTE: <cvr-qualifiers> here is always 'B' (const). <storage-class>
  // is always '6' for vftables.
  MicrosoftCXXNameMangler Mangler(*this, Out);
  Mangler.getStream() << "\01??_7";
  Mangler.mangleName(RD);
  Mangler.getStream() << "6B";  // '6' for vftable, 'B' for const.
  // TODO: If the class has more than one vtable, mangle in the class it came
  // from.
  Mangler.getStream() << '@';
}

void MicrosoftMangleContext::mangleCXXVBTable(
    const CXXRecordDecl *Derived, ArrayRef<const CXXRecordDecl *> BasePath,
    raw_ostream &Out) {
  // <mangled-name> ::= ?_8 <class-name> <storage-class>
  //                    <cvr-qualifiers> [<name>] @
  // NOTE: <cvr-qualifiers> here is always 'B' (const). <storage-class>
  // is always '7' for vbtables.
  MicrosoftCXXNameMangler Mangler(*this, Out);
  Mangler.getStream() << "\01??_8";
  Mangler.mangleName(Derived);
  Mangler.getStream() << "7B";  // '7' for vbtable, 'B' for const.
  for (ArrayRef<const CXXRecordDecl *>::iterator I = BasePath.begin(),
                                                 E = BasePath.end();
       I != E; ++I) {
    Mangler.mangleName(*I);
  }
  Mangler.getStream() << '@';
}

void MicrosoftMangleContext::mangleCXXVTT(const CXXRecordDecl *RD,
                                          raw_ostream &) {
  llvm_unreachable("The MS C++ ABI does not have virtual table tables!");
}
void MicrosoftMangleContext::mangleCXXCtorVTable(const CXXRecordDecl *RD,
                                                 int64_t Offset,
                                                 const CXXRecordDecl *Type,
                                                 raw_ostream &) {
  llvm_unreachable("The MS C++ ABI does not have constructor vtables!");
}
void MicrosoftMangleContext::mangleCXXRTTI(QualType T,
                                           raw_ostream &) {
  // FIXME: Give a location...
  unsigned DiagID = getDiags().getCustomDiagID(DiagnosticsEngine::Error,
    "cannot mangle RTTI descriptors for type %0 yet");
  getDiags().Report(DiagID)
    << T.getBaseTypeIdentifier();
}
void MicrosoftMangleContext::mangleCXXRTTIName(QualType T,
                                               raw_ostream &) {
  // FIXME: Give a location...
  unsigned DiagID = getDiags().getCustomDiagID(DiagnosticsEngine::Error,
    "cannot mangle the name of type %0 into RTTI descriptors yet");
  getDiags().Report(DiagID)
    << T.getBaseTypeIdentifier();
}
void MicrosoftMangleContext::mangleCXXCtor(const CXXConstructorDecl *D,
                                           CXXCtorType Type,
                                           raw_ostream & Out) {
  MicrosoftCXXNameMangler mangler(*this, Out);
  mangler.mangle(D);
}
void MicrosoftMangleContext::mangleCXXDtor(const CXXDestructorDecl *D,
                                           CXXDtorType Type,
                                           raw_ostream & Out) {
  MicrosoftCXXNameMangler mangler(*this, Out, D, Type);
  mangler.mangle(D);
}
void MicrosoftMangleContext::mangleReferenceTemporary(const clang::VarDecl *VD,
                                                      raw_ostream &) {
  unsigned DiagID = getDiags().getCustomDiagID(DiagnosticsEngine::Error,
    "cannot mangle this reference temporary yet");
  getDiags().Report(VD->getLocation(), DiagID);
}

MangleContext *clang::createMicrosoftMangleContext(ASTContext &Context,
                                                   DiagnosticsEngine &Diags) {
  return new MicrosoftMangleContext(Context, Diags);
}

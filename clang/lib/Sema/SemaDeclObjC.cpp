//===--- SemaDeclObjC.cpp - Semantic Analysis for ObjC Declarations -------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file implements semantic analysis for Objective C declarations.
//
//===----------------------------------------------------------------------===//

#include "clang/Sema/SemaInternal.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/ASTMutationListener.h"
#include "clang/AST/DeclObjC.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprObjC.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Sema/DeclSpec.h"
#include "clang/Sema/ExternalSemaSource.h"
#include "clang/Sema/Lookup.h"
#include "clang/Sema/Scope.h"
#include "clang/Sema/ScopeInfo.h"
#include "llvm/ADT/DenseSet.h"

using namespace clang;

/// Check whether the given method, which must be in the 'init'
/// family, is a valid member of that family.
///
/// \param receiverTypeIfCall - if null, check this as if declaring it;
///   if non-null, check this as if making a call to it with the given
///   receiver type
///
/// \return true to indicate that there was an error and appropriate
///   actions were taken
bool Sema::checkInitMethod(ObjCMethodDecl *method,
                           QualType receiverTypeIfCall) {
  if (method->isInvalidDecl()) return true;

  // This castAs is safe: methods that don't return an object
  // pointer won't be inferred as inits and will reject an explicit
  // objc_method_family(init).

  // We ignore protocols here.  Should we?  What about Class?

  const ObjCObjectType *result = method->getResultType()
    ->castAs<ObjCObjectPointerType>()->getObjectType();

  if (result->isObjCId()) {
    return false;
  } else if (result->isObjCClass()) {
    // fall through: always an error
  } else {
    ObjCInterfaceDecl *resultClass = result->getInterface();
    assert(resultClass && "unexpected object type!");

    // It's okay for the result type to still be a forward declaration
    // if we're checking an interface declaration.
    if (!resultClass->hasDefinition()) {
      if (receiverTypeIfCall.isNull() &&
          !isa<ObjCImplementationDecl>(method->getDeclContext()))
        return false;

    // Otherwise, we try to compare class types.
    } else {
      // If this method was declared in a protocol, we can't check
      // anything unless we have a receiver type that's an interface.
      const ObjCInterfaceDecl *receiverClass = 0;
      if (isa<ObjCProtocolDecl>(method->getDeclContext())) {
        if (receiverTypeIfCall.isNull())
          return false;

        receiverClass = receiverTypeIfCall->castAs<ObjCObjectPointerType>()
          ->getInterfaceDecl();

        // This can be null for calls to e.g. id<Foo>.
        if (!receiverClass) return false;
      } else {
        receiverClass = method->getClassInterface();
        assert(receiverClass && "method not associated with a class!");
      }

      // If either class is a subclass of the other, it's fine.
      if (receiverClass->isSuperClassOf(resultClass) ||
          resultClass->isSuperClassOf(receiverClass))
        return false;
    }
  }

  SourceLocation loc = method->getLocation();

  // If we're in a system header, and this is not a call, just make
  // the method unusable.
  if (receiverTypeIfCall.isNull() && getSourceManager().isInSystemHeader(loc)) {
    method->addAttr(new (Context) UnavailableAttr(loc, Context,
                "init method returns a type unrelated to its receiver type"));
    return true;
  }

  // Otherwise, it's an error.
  Diag(loc, diag::err_arc_init_method_unrelated_result_type);
  method->setInvalidDecl();
  return true;
}

void Sema::CheckObjCMethodOverride(ObjCMethodDecl *NewMethod, 
                                   const ObjCMethodDecl *Overridden) {
  if (Overridden->hasRelatedResultType() && 
      !NewMethod->hasRelatedResultType()) {
    // This can only happen when the method follows a naming convention that
    // implies a related result type, and the original (overridden) method has
    // a suitable return type, but the new (overriding) method does not have
    // a suitable return type.
    QualType ResultType = NewMethod->getResultType();
    SourceRange ResultTypeRange;
    if (const TypeSourceInfo *ResultTypeInfo 
                                        = NewMethod->getResultTypeSourceInfo())
      ResultTypeRange = ResultTypeInfo->getTypeLoc().getSourceRange();
    
    // Figure out which class this method is part of, if any.
    ObjCInterfaceDecl *CurrentClass 
      = dyn_cast<ObjCInterfaceDecl>(NewMethod->getDeclContext());
    if (!CurrentClass) {
      DeclContext *DC = NewMethod->getDeclContext();
      if (ObjCCategoryDecl *Cat = dyn_cast<ObjCCategoryDecl>(DC))
        CurrentClass = Cat->getClassInterface();
      else if (ObjCImplDecl *Impl = dyn_cast<ObjCImplDecl>(DC))
        CurrentClass = Impl->getClassInterface();
      else if (ObjCCategoryImplDecl *CatImpl
               = dyn_cast<ObjCCategoryImplDecl>(DC))
        CurrentClass = CatImpl->getClassInterface();
    }
    
    if (CurrentClass) {
      Diag(NewMethod->getLocation(), 
           diag::warn_related_result_type_compatibility_class)
        << Context.getObjCInterfaceType(CurrentClass)
        << ResultType
        << ResultTypeRange;
    } else {
      Diag(NewMethod->getLocation(), 
           diag::warn_related_result_type_compatibility_protocol)
        << ResultType
        << ResultTypeRange;
    }
    
    if (ObjCMethodFamily Family = Overridden->getMethodFamily())
      Diag(Overridden->getLocation(), 
           diag::note_related_result_type_family)
        << /*overridden method*/ 0
        << Family;
    else
      Diag(Overridden->getLocation(), 
           diag::note_related_result_type_overridden);
  }
  if (getLangOpts().ObjCAutoRefCount) {
    if ((NewMethod->hasAttr<NSReturnsRetainedAttr>() !=
         Overridden->hasAttr<NSReturnsRetainedAttr>())) {
        Diag(NewMethod->getLocation(),
             diag::err_nsreturns_retained_attribute_mismatch) << 1;
        Diag(Overridden->getLocation(), diag::note_previous_decl) 
        << "method";
    }
    if ((NewMethod->hasAttr<NSReturnsNotRetainedAttr>() !=
              Overridden->hasAttr<NSReturnsNotRetainedAttr>())) {
        Diag(NewMethod->getLocation(),
             diag::err_nsreturns_retained_attribute_mismatch) << 0;
        Diag(Overridden->getLocation(), diag::note_previous_decl) 
        << "method";
    }
    ObjCMethodDecl::param_const_iterator oi = Overridden->param_begin(),
                                         oe = Overridden->param_end();
    for (ObjCMethodDecl::param_iterator
           ni = NewMethod->param_begin(), ne = NewMethod->param_end();
         ni != ne && oi != oe; ++ni, ++oi) {
      const ParmVarDecl *oldDecl = (*oi);
      ParmVarDecl *newDecl = (*ni);
      if (newDecl->hasAttr<NSConsumedAttr>() != 
          oldDecl->hasAttr<NSConsumedAttr>()) {
        Diag(newDecl->getLocation(),
             diag::err_nsconsumed_attribute_mismatch);
        Diag(oldDecl->getLocation(), diag::note_previous_decl) 
          << "parameter";
      }
    }
  }
}

/// \brief Check a method declaration for compatibility with the Objective-C
/// ARC conventions.
bool Sema::CheckARCMethodDecl(ObjCMethodDecl *method) {
  ObjCMethodFamily family = method->getMethodFamily();
  switch (family) {
  case OMF_None:
  case OMF_finalize:
  case OMF_retain:
  case OMF_release:
  case OMF_autorelease:
  case OMF_retainCount:
  case OMF_self:
  case OMF_performSelector:
    return false;

  case OMF_dealloc:
    if (!Context.hasSameType(method->getResultType(), Context.VoidTy)) {
      SourceRange ResultTypeRange;
      if (const TypeSourceInfo *ResultTypeInfo
          = method->getResultTypeSourceInfo())
        ResultTypeRange = ResultTypeInfo->getTypeLoc().getSourceRange();
      if (ResultTypeRange.isInvalid())
        Diag(method->getLocation(), diag::error_dealloc_bad_result_type) 
          << method->getResultType() 
          << FixItHint::CreateInsertion(method->getSelectorLoc(0), "(void)");
      else
        Diag(method->getLocation(), diag::error_dealloc_bad_result_type) 
          << method->getResultType() 
          << FixItHint::CreateReplacement(ResultTypeRange, "void");
      return true;
    }
    return false;
      
  case OMF_init:
    // If the method doesn't obey the init rules, don't bother annotating it.
    if (checkInitMethod(method, QualType()))
      return true;

    method->addAttr(new (Context) NSConsumesSelfAttr(SourceLocation(),
                                                     Context));

    // Don't add a second copy of this attribute, but otherwise don't
    // let it be suppressed.
    if (method->hasAttr<NSReturnsRetainedAttr>())
      return false;
    break;

  case OMF_alloc:
  case OMF_copy:
  case OMF_mutableCopy:
  case OMF_new:
    if (method->hasAttr<NSReturnsRetainedAttr>() ||
        method->hasAttr<NSReturnsNotRetainedAttr>() ||
        method->hasAttr<NSReturnsAutoreleasedAttr>())
      return false;
    break;
  }

  method->addAttr(new (Context) NSReturnsRetainedAttr(SourceLocation(),
                                                      Context));
  return false;
}

static void DiagnoseObjCImplementedDeprecations(Sema &S,
                                                NamedDecl *ND,
                                                SourceLocation ImplLoc,
                                                int select) {
  if (ND && ND->isDeprecated()) {
    S.Diag(ImplLoc, diag::warn_deprecated_def) << select;
    if (select == 0)
      S.Diag(ND->getLocation(), diag::note_method_declared_at)
        << ND->getDeclName();
    else
      S.Diag(ND->getLocation(), diag::note_previous_decl) << "class";
  }
}

/// AddAnyMethodToGlobalPool - Add any method, instance or factory to global
/// pool.
void Sema::AddAnyMethodToGlobalPool(Decl *D) {
  ObjCMethodDecl *MDecl = dyn_cast_or_null<ObjCMethodDecl>(D);
    
  // If we don't have a valid method decl, simply return.
  if (!MDecl)
    return;
  if (MDecl->isInstanceMethod())
    AddInstanceMethodToGlobalPool(MDecl, true);
  else
    AddFactoryMethodToGlobalPool(MDecl, true);
}

/// HasExplicitOwnershipAttr - returns true when pointer to ObjC pointer
/// has explicit ownership attribute; false otherwise.
static bool
HasExplicitOwnershipAttr(Sema &S, ParmVarDecl *Param) {
  QualType T = Param->getType();
  
  if (const PointerType *PT = T->getAs<PointerType>()) {
    T = PT->getPointeeType();
  } else if (const ReferenceType *RT = T->getAs<ReferenceType>()) {
    T = RT->getPointeeType();
  } else {
    return true;
  }
  
  // If we have a lifetime qualifier, but it's local, we must have 
  // inferred it. So, it is implicit.
  return !T.getLocalQualifiers().hasObjCLifetime();
}

/// ActOnStartOfObjCMethodDef - This routine sets up parameters; invisible
/// and user declared, in the method definition's AST.
void Sema::ActOnStartOfObjCMethodDef(Scope *FnBodyScope, Decl *D) {
  assert((getCurMethodDecl() == 0) && "Methodparsing confused");
  ObjCMethodDecl *MDecl = dyn_cast_or_null<ObjCMethodDecl>(D);
  
  // If we don't have a valid method decl, simply return.
  if (!MDecl)
    return;

  // Allow all of Sema to see that we are entering a method definition.
  PushDeclContext(FnBodyScope, MDecl);
  PushFunctionScope();
  
  // Create Decl objects for each parameter, entrring them in the scope for
  // binding to their use.

  // Insert the invisible arguments, self and _cmd!
  MDecl->createImplicitParams(Context, MDecl->getClassInterface());

  PushOnScopeChains(MDecl->getSelfDecl(), FnBodyScope);
  PushOnScopeChains(MDecl->getCmdDecl(), FnBodyScope);

  // Introduce all of the other parameters into this scope.
  for (ObjCMethodDecl::param_iterator PI = MDecl->param_begin(),
       E = MDecl->param_end(); PI != E; ++PI) {
    ParmVarDecl *Param = (*PI);
    if (!Param->isInvalidDecl() &&
        RequireCompleteType(Param->getLocation(), Param->getType(),
                            diag::err_typecheck_decl_incomplete_type))
          Param->setInvalidDecl();
    if (!Param->isInvalidDecl() &&
        getLangOpts().ObjCAutoRefCount &&
        !HasExplicitOwnershipAttr(*this, Param))
      Diag(Param->getLocation(), diag::warn_arc_strong_pointer_objc_pointer) <<
            Param->getType();
    
    if ((*PI)->getIdentifier())
      PushOnScopeChains(*PI, FnBodyScope);
  }

  // In ARC, disallow definition of retain/release/autorelease/retainCount
  if (getLangOpts().ObjCAutoRefCount) {
    switch (MDecl->getMethodFamily()) {
    case OMF_retain:
    case OMF_retainCount:
    case OMF_release:
    case OMF_autorelease:
      Diag(MDecl->getLocation(), diag::err_arc_illegal_method_def)
        << 0 << MDecl->getSelector();
      break;

    case OMF_None:
    case OMF_dealloc:
    case OMF_finalize:
    case OMF_alloc:
    case OMF_init:
    case OMF_mutableCopy:
    case OMF_copy:
    case OMF_new:
    case OMF_self:
    case OMF_performSelector:
      break;
    }
  }

  // Warn on deprecated methods under -Wdeprecated-implementations,
  // and prepare for warning on missing super calls.
  if (ObjCInterfaceDecl *IC = MDecl->getClassInterface()) {
    ObjCMethodDecl *IMD = 
      IC->lookupMethod(MDecl->getSelector(), MDecl->isInstanceMethod());
    
    if (IMD) {
      ObjCImplDecl *ImplDeclOfMethodDef = 
        dyn_cast<ObjCImplDecl>(MDecl->getDeclContext());
      ObjCContainerDecl *ContDeclOfMethodDecl = 
        dyn_cast<ObjCContainerDecl>(IMD->getDeclContext());
      ObjCImplDecl *ImplDeclOfMethodDecl = 0;
      if (ObjCInterfaceDecl *OID = dyn_cast<ObjCInterfaceDecl>(ContDeclOfMethodDecl))
        ImplDeclOfMethodDecl = OID->getImplementation();
      else if (ObjCCategoryDecl *CD = dyn_cast<ObjCCategoryDecl>(ContDeclOfMethodDecl))
        ImplDeclOfMethodDecl = CD->getImplementation();
      // No need to issue deprecated warning if deprecated mehod in class/category
      // is being implemented in its own implementation (no overriding is involved).
      if (!ImplDeclOfMethodDecl || ImplDeclOfMethodDecl != ImplDeclOfMethodDef)
        DiagnoseObjCImplementedDeprecations(*this, 
                                          dyn_cast<NamedDecl>(IMD), 
                                          MDecl->getLocation(), 0);
    }

    // If this is "dealloc" or "finalize", set some bit here.
    // Then in ActOnSuperMessage() (SemaExprObjC), set it back to false.
    // Finally, in ActOnFinishFunctionBody() (SemaDecl), warn if flag is set.
    // Only do this if the current class actually has a superclass.
    if (const ObjCInterfaceDecl *SuperClass = IC->getSuperClass()) {
      ObjCMethodFamily Family = MDecl->getMethodFamily();
      if (Family == OMF_dealloc) {
        if (!(getLangOpts().ObjCAutoRefCount ||
              getLangOpts().getGC() == LangOptions::GCOnly))
          getCurFunction()->ObjCShouldCallSuper = true;

      } else if (Family == OMF_finalize) {
        if (Context.getLangOpts().getGC() != LangOptions::NonGC)
          getCurFunction()->ObjCShouldCallSuper = true;
        
      } else {
        const ObjCMethodDecl *SuperMethod =
          SuperClass->lookupMethod(MDecl->getSelector(),
                                   MDecl->isInstanceMethod());
        getCurFunction()->ObjCShouldCallSuper = 
          (SuperMethod && SuperMethod->hasAttr<ObjCRequiresSuperAttr>());
      }
    }
  }
}

namespace {

// Callback to only accept typo corrections that are Objective-C classes.
// If an ObjCInterfaceDecl* is given to the constructor, then the validation
// function will reject corrections to that class.
class ObjCInterfaceValidatorCCC : public CorrectionCandidateCallback {
 public:
  ObjCInterfaceValidatorCCC() : CurrentIDecl(0) {}
  explicit ObjCInterfaceValidatorCCC(ObjCInterfaceDecl *IDecl)
      : CurrentIDecl(IDecl) {}

  virtual bool ValidateCandidate(const TypoCorrection &candidate) {
    ObjCInterfaceDecl *ID = candidate.getCorrectionDeclAs<ObjCInterfaceDecl>();
    return ID && !declaresSameEntity(ID, CurrentIDecl);
  }

 private:
  ObjCInterfaceDecl *CurrentIDecl;
};

}

Decl *Sema::
ActOnStartClassInterface(SourceLocation AtInterfaceLoc,
                         IdentifierInfo *ClassName, SourceLocation ClassLoc,
                         IdentifierInfo *SuperName, SourceLocation SuperLoc,
                         Decl * const *ProtoRefs, unsigned NumProtoRefs,
                         const SourceLocation *ProtoLocs, 
                         SourceLocation EndProtoLoc, AttributeList *AttrList) {
  assert(ClassName && "Missing class identifier");

  // Check for another declaration kind with the same name.
  NamedDecl *PrevDecl = LookupSingleName(TUScope, ClassName, ClassLoc,
                                         LookupOrdinaryName, ForRedeclaration);

  if (PrevDecl && !isa<ObjCInterfaceDecl>(PrevDecl)) {
    Diag(ClassLoc, diag::err_redefinition_different_kind) << ClassName;
    Diag(PrevDecl->getLocation(), diag::note_previous_definition);
  }

  // Create a declaration to describe this @interface.
  ObjCInterfaceDecl* PrevIDecl = dyn_cast_or_null<ObjCInterfaceDecl>(PrevDecl);

  if (PrevIDecl && PrevIDecl->getIdentifier() != ClassName) {
    // A previous decl with a different name is because of
    // @compatibility_alias, for example:
    // \code
    //   @class NewImage;
    //   @compatibility_alias OldImage NewImage;
    // \endcode
    // A lookup for 'OldImage' will return the 'NewImage' decl.
    //
    // In such a case use the real declaration name, instead of the alias one,
    // otherwise we will break IdentifierResolver and redecls-chain invariants.
    // FIXME: If necessary, add a bit to indicate that this ObjCInterfaceDecl
    // has been aliased.
    ClassName = PrevIDecl->getIdentifier();
  }

  ObjCInterfaceDecl *IDecl
    = ObjCInterfaceDecl::Create(Context, CurContext, AtInterfaceLoc, ClassName,
                                PrevIDecl, ClassLoc);
  
  if (PrevIDecl) {
    // Class already seen. Was it a definition?
    if (ObjCInterfaceDecl *Def = PrevIDecl->getDefinition()) {
      Diag(AtInterfaceLoc, diag::err_duplicate_class_def)
        << PrevIDecl->getDeclName();
      Diag(Def->getLocation(), diag::note_previous_definition);
      IDecl->setInvalidDecl();
    }
  }
  
  if (AttrList)
    ProcessDeclAttributeList(TUScope, IDecl, AttrList);
  PushOnScopeChains(IDecl, TUScope);

  // Start the definition of this class. If we're in a redefinition case, there 
  // may already be a definition, so we'll end up adding to it.
  if (!IDecl->hasDefinition())
    IDecl->startDefinition();
  
  if (SuperName) {
    // Check if a different kind of symbol declared in this scope.
    PrevDecl = LookupSingleName(TUScope, SuperName, SuperLoc,
                                LookupOrdinaryName);

    if (!PrevDecl) {
      // Try to correct for a typo in the superclass name without correcting
      // to the class we're defining.
      ObjCInterfaceValidatorCCC Validator(IDecl);
      if (TypoCorrection Corrected = CorrectTypo(
          DeclarationNameInfo(SuperName, SuperLoc), LookupOrdinaryName, TUScope,
          NULL, Validator)) {
        PrevDecl = Corrected.getCorrectionDeclAs<ObjCInterfaceDecl>();
        Diag(SuperLoc, diag::err_undef_superclass_suggest)
          << SuperName << ClassName << PrevDecl->getDeclName();
        Diag(PrevDecl->getLocation(), diag::note_previous_decl)
          << PrevDecl->getDeclName();
      }
    }

    if (declaresSameEntity(PrevDecl, IDecl)) {
      Diag(SuperLoc, diag::err_recursive_superclass)
        << SuperName << ClassName << SourceRange(AtInterfaceLoc, ClassLoc);
      IDecl->setEndOfDefinitionLoc(ClassLoc);
    } else {
      ObjCInterfaceDecl *SuperClassDecl =
                                dyn_cast_or_null<ObjCInterfaceDecl>(PrevDecl);

      // Diagnose classes that inherit from deprecated classes.
      if (SuperClassDecl)
        (void)DiagnoseUseOfDecl(SuperClassDecl, SuperLoc);

      if (PrevDecl && SuperClassDecl == 0) {
        // The previous declaration was not a class decl. Check if we have a
        // typedef. If we do, get the underlying class type.
        if (const TypedefNameDecl *TDecl =
              dyn_cast_or_null<TypedefNameDecl>(PrevDecl)) {
          QualType T = TDecl->getUnderlyingType();
          if (T->isObjCObjectType()) {
            if (NamedDecl *IDecl = T->getAs<ObjCObjectType>()->getInterface()) {
              SuperClassDecl = dyn_cast<ObjCInterfaceDecl>(IDecl);
              // This handles the following case:
              // @interface NewI @end
              // typedef NewI DeprI __attribute__((deprecated("blah")))
              // @interface SI : DeprI /* warn here */ @end
              (void)DiagnoseUseOfDecl(const_cast<TypedefNameDecl*>(TDecl), SuperLoc);
            }
          }
        }

        // This handles the following case:
        //
        // typedef int SuperClass;
        // @interface MyClass : SuperClass {} @end
        //
        if (!SuperClassDecl) {
          Diag(SuperLoc, diag::err_redefinition_different_kind) << SuperName;
          Diag(PrevDecl->getLocation(), diag::note_previous_definition);
        }
      }

      if (!dyn_cast_or_null<TypedefNameDecl>(PrevDecl)) {
        if (!SuperClassDecl)
          Diag(SuperLoc, diag::err_undef_superclass)
            << SuperName << ClassName << SourceRange(AtInterfaceLoc, ClassLoc);
        else if (RequireCompleteType(SuperLoc, 
                                  Context.getObjCInterfaceType(SuperClassDecl),
                                     diag::err_forward_superclass,
                                     SuperClassDecl->getDeclName(),
                                     ClassName,
                                     SourceRange(AtInterfaceLoc, ClassLoc))) {
          SuperClassDecl = 0;
        }
      }
      IDecl->setSuperClass(SuperClassDecl);
      IDecl->setSuperClassLoc(SuperLoc);
      IDecl->setEndOfDefinitionLoc(SuperLoc);
    }
  } else { // we have a root class.
    IDecl->setEndOfDefinitionLoc(ClassLoc);
  }

  // Check then save referenced protocols.
  if (NumProtoRefs) {
    IDecl->setProtocolList((ObjCProtocolDecl*const*)ProtoRefs, NumProtoRefs,
                           ProtoLocs, Context);
    IDecl->setEndOfDefinitionLoc(EndProtoLoc);
  }

  CheckObjCDeclScope(IDecl);
  return ActOnObjCContainerStartDefinition(IDecl);
}

/// ActOnCompatibilityAlias - this action is called after complete parsing of
/// a \@compatibility_alias declaration. It sets up the alias relationships.
Decl *Sema::ActOnCompatibilityAlias(SourceLocation AtLoc,
                                    IdentifierInfo *AliasName,
                                    SourceLocation AliasLocation,
                                    IdentifierInfo *ClassName,
                                    SourceLocation ClassLocation) {
  // Look for previous declaration of alias name
  NamedDecl *ADecl = LookupSingleName(TUScope, AliasName, AliasLocation,
                                      LookupOrdinaryName, ForRedeclaration);
  if (ADecl) {
    Diag(AliasLocation, diag::err_conflicting_aliasing_type) << AliasName;
    Diag(ADecl->getLocation(), diag::note_previous_declaration);
    return 0;
  }
  // Check for class declaration
  NamedDecl *CDeclU = LookupSingleName(TUScope, ClassName, ClassLocation,
                                       LookupOrdinaryName, ForRedeclaration);
  if (const TypedefNameDecl *TDecl =
        dyn_cast_or_null<TypedefNameDecl>(CDeclU)) {
    QualType T = TDecl->getUnderlyingType();
    if (T->isObjCObjectType()) {
      if (NamedDecl *IDecl = T->getAs<ObjCObjectType>()->getInterface()) {
        ClassName = IDecl->getIdentifier();
        CDeclU = LookupSingleName(TUScope, ClassName, ClassLocation,
                                  LookupOrdinaryName, ForRedeclaration);
      }
    }
  }
  ObjCInterfaceDecl *CDecl = dyn_cast_or_null<ObjCInterfaceDecl>(CDeclU);
  if (CDecl == 0) {
    Diag(ClassLocation, diag::warn_undef_interface) << ClassName;
    if (CDeclU)
      Diag(CDeclU->getLocation(), diag::note_previous_declaration);
    return 0;
  }

  // Everything checked out, instantiate a new alias declaration AST.
  ObjCCompatibleAliasDecl *AliasDecl =
    ObjCCompatibleAliasDecl::Create(Context, CurContext, AtLoc, AliasName, CDecl);

  if (!CheckObjCDeclScope(AliasDecl))
    PushOnScopeChains(AliasDecl, TUScope);

  return AliasDecl;
}

bool Sema::CheckForwardProtocolDeclarationForCircularDependency(
  IdentifierInfo *PName,
  SourceLocation &Ploc, SourceLocation PrevLoc,
  const ObjCList<ObjCProtocolDecl> &PList) {
  
  bool res = false;
  for (ObjCList<ObjCProtocolDecl>::iterator I = PList.begin(),
       E = PList.end(); I != E; ++I) {
    if (ObjCProtocolDecl *PDecl = LookupProtocol((*I)->getIdentifier(),
                                                 Ploc)) {
      if (PDecl->getIdentifier() == PName) {
        Diag(Ploc, diag::err_protocol_has_circular_dependency);
        Diag(PrevLoc, diag::note_previous_definition);
        res = true;
      }
      
      if (!PDecl->hasDefinition())
        continue;
      
      if (CheckForwardProtocolDeclarationForCircularDependency(PName, Ploc,
            PDecl->getLocation(), PDecl->getReferencedProtocols()))
        res = true;
    }
  }
  return res;
}

Decl *
Sema::ActOnStartProtocolInterface(SourceLocation AtProtoInterfaceLoc,
                                  IdentifierInfo *ProtocolName,
                                  SourceLocation ProtocolLoc,
                                  Decl * const *ProtoRefs,
                                  unsigned NumProtoRefs,
                                  const SourceLocation *ProtoLocs,
                                  SourceLocation EndProtoLoc,
                                  AttributeList *AttrList) {
  bool err = false;
  // FIXME: Deal with AttrList.
  assert(ProtocolName && "Missing protocol identifier");
  ObjCProtocolDecl *PrevDecl = LookupProtocol(ProtocolName, ProtocolLoc,
                                              ForRedeclaration);
  ObjCProtocolDecl *PDecl = 0;
  if (ObjCProtocolDecl *Def = PrevDecl? PrevDecl->getDefinition() : 0) {
    // If we already have a definition, complain.
    Diag(ProtocolLoc, diag::warn_duplicate_protocol_def) << ProtocolName;
    Diag(Def->getLocation(), diag::note_previous_definition);

    // Create a new protocol that is completely distinct from previous
    // declarations, and do not make this protocol available for name lookup.
    // That way, we'll end up completely ignoring the duplicate.
    // FIXME: Can we turn this into an error?
    PDecl = ObjCProtocolDecl::Create(Context, CurContext, ProtocolName,
                                     ProtocolLoc, AtProtoInterfaceLoc,
                                     /*PrevDecl=*/0);
    PDecl->startDefinition();
  } else {
    if (PrevDecl) {
      // Check for circular dependencies among protocol declarations. This can
      // only happen if this protocol was forward-declared.
      ObjCList<ObjCProtocolDecl> PList;
      PList.set((ObjCProtocolDecl *const*)ProtoRefs, NumProtoRefs, Context);
      err = CheckForwardProtocolDeclarationForCircularDependency(
              ProtocolName, ProtocolLoc, PrevDecl->getLocation(), PList);
    }

    // Create the new declaration.
    PDecl = ObjCProtocolDecl::Create(Context, CurContext, ProtocolName,
                                     ProtocolLoc, AtProtoInterfaceLoc,
                                     /*PrevDecl=*/PrevDecl);
    
    PushOnScopeChains(PDecl, TUScope);
    PDecl->startDefinition();
  }
  
  if (AttrList)
    ProcessDeclAttributeList(TUScope, PDecl, AttrList);
  
  // Merge attributes from previous declarations.
  if (PrevDecl)
    mergeDeclAttributes(PDecl, PrevDecl);

  if (!err && NumProtoRefs ) {
    /// Check then save referenced protocols.
    PDecl->setProtocolList((ObjCProtocolDecl*const*)ProtoRefs, NumProtoRefs,
                           ProtoLocs, Context);
  }

  CheckObjCDeclScope(PDecl);
  return ActOnObjCContainerStartDefinition(PDecl);
}

/// FindProtocolDeclaration - This routine looks up protocols and
/// issues an error if they are not declared. It returns list of
/// protocol declarations in its 'Protocols' argument.
void
Sema::FindProtocolDeclaration(bool WarnOnDeclarations,
                              const IdentifierLocPair *ProtocolId,
                              unsigned NumProtocols,
                              SmallVectorImpl<Decl *> &Protocols) {
  for (unsigned i = 0; i != NumProtocols; ++i) {
    ObjCProtocolDecl *PDecl = LookupProtocol(ProtocolId[i].first,
                                             ProtocolId[i].second);
    if (!PDecl) {
      DeclFilterCCC<ObjCProtocolDecl> Validator;
      TypoCorrection Corrected = CorrectTypo(
          DeclarationNameInfo(ProtocolId[i].first, ProtocolId[i].second),
          LookupObjCProtocolName, TUScope, NULL, Validator);
      if ((PDecl = Corrected.getCorrectionDeclAs<ObjCProtocolDecl>())) {
        Diag(ProtocolId[i].second, diag::err_undeclared_protocol_suggest)
          << ProtocolId[i].first << Corrected.getCorrection();
        Diag(PDecl->getLocation(), diag::note_previous_decl)
          << PDecl->getDeclName();
      }
    }

    if (!PDecl) {
      Diag(ProtocolId[i].second, diag::err_undeclared_protocol)
        << ProtocolId[i].first;
      continue;
    }
    // If this is a forward protocol declaration, get its definition.
    if (!PDecl->isThisDeclarationADefinition() && PDecl->getDefinition())
      PDecl = PDecl->getDefinition();
    
    (void)DiagnoseUseOfDecl(PDecl, ProtocolId[i].second);

    // If this is a forward declaration and we are supposed to warn in this
    // case, do it.
    // FIXME: Recover nicely in the hidden case.
    if (WarnOnDeclarations &&
        (!PDecl->hasDefinition() || PDecl->getDefinition()->isHidden()))
      Diag(ProtocolId[i].second, diag::warn_undef_protocolref)
        << ProtocolId[i].first;
    Protocols.push_back(PDecl);
  }
}

/// DiagnoseClassExtensionDupMethods - Check for duplicate declaration of
/// a class method in its extension.
///
void Sema::DiagnoseClassExtensionDupMethods(ObjCCategoryDecl *CAT,
                                            ObjCInterfaceDecl *ID) {
  if (!ID)
    return;  // Possibly due to previous error

  llvm::DenseMap<Selector, const ObjCMethodDecl*> MethodMap;
  for (ObjCInterfaceDecl::method_iterator i = ID->meth_begin(),
       e =  ID->meth_end(); i != e; ++i) {
    ObjCMethodDecl *MD = *i;
    MethodMap[MD->getSelector()] = MD;
  }

  if (MethodMap.empty())
    return;
  for (ObjCCategoryDecl::method_iterator i = CAT->meth_begin(),
       e =  CAT->meth_end(); i != e; ++i) {
    ObjCMethodDecl *Method = *i;
    const ObjCMethodDecl *&PrevMethod = MethodMap[Method->getSelector()];
    if (PrevMethod && !MatchTwoMethodDeclarations(Method, PrevMethod)) {
      Diag(Method->getLocation(), diag::err_duplicate_method_decl)
            << Method->getDeclName();
      Diag(PrevMethod->getLocation(), diag::note_previous_declaration);
    }
  }
}

/// ActOnForwardProtocolDeclaration - Handle \@protocol foo;
Sema::DeclGroupPtrTy
Sema::ActOnForwardProtocolDeclaration(SourceLocation AtProtocolLoc,
                                      const IdentifierLocPair *IdentList,
                                      unsigned NumElts,
                                      AttributeList *attrList) {
  SmallVector<Decl *, 8> DeclsInGroup;
  for (unsigned i = 0; i != NumElts; ++i) {
    IdentifierInfo *Ident = IdentList[i].first;
    ObjCProtocolDecl *PrevDecl = LookupProtocol(Ident, IdentList[i].second,
                                                ForRedeclaration);
    ObjCProtocolDecl *PDecl
      = ObjCProtocolDecl::Create(Context, CurContext, Ident, 
                                 IdentList[i].second, AtProtocolLoc,
                                 PrevDecl);
        
    PushOnScopeChains(PDecl, TUScope);
    CheckObjCDeclScope(PDecl);
    
    if (attrList)
      ProcessDeclAttributeList(TUScope, PDecl, attrList);
    
    if (PrevDecl)
      mergeDeclAttributes(PDecl, PrevDecl);

    DeclsInGroup.push_back(PDecl);
  }

  return BuildDeclaratorGroup(DeclsInGroup.data(), DeclsInGroup.size(), false);
}

Decl *Sema::
ActOnStartCategoryInterface(SourceLocation AtInterfaceLoc,
                            IdentifierInfo *ClassName, SourceLocation ClassLoc,
                            IdentifierInfo *CategoryName,
                            SourceLocation CategoryLoc,
                            Decl * const *ProtoRefs,
                            unsigned NumProtoRefs,
                            const SourceLocation *ProtoLocs,
                            SourceLocation EndProtoLoc) {
  ObjCCategoryDecl *CDecl;
  ObjCInterfaceDecl *IDecl = getObjCInterfaceDecl(ClassName, ClassLoc, true);

  /// Check that class of this category is already completely declared.

  if (!IDecl 
      || RequireCompleteType(ClassLoc, Context.getObjCInterfaceType(IDecl),
                             diag::err_category_forward_interface,
                             CategoryName == 0)) {
    // Create an invalid ObjCCategoryDecl to serve as context for
    // the enclosing method declarations.  We mark the decl invalid
    // to make it clear that this isn't a valid AST.
    CDecl = ObjCCategoryDecl::Create(Context, CurContext, AtInterfaceLoc,
                                     ClassLoc, CategoryLoc, CategoryName,IDecl);
    CDecl->setInvalidDecl();
    CurContext->addDecl(CDecl);
        
    if (!IDecl)
      Diag(ClassLoc, diag::err_undef_interface) << ClassName;
    return ActOnObjCContainerStartDefinition(CDecl);
  }

  if (!CategoryName && IDecl->getImplementation()) {
    Diag(ClassLoc, diag::err_class_extension_after_impl) << ClassName;
    Diag(IDecl->getImplementation()->getLocation(), 
          diag::note_implementation_declared);
  }

  if (CategoryName) {
    /// Check for duplicate interface declaration for this category
    if (ObjCCategoryDecl *Previous
          = IDecl->FindCategoryDeclaration(CategoryName)) {
      // Class extensions can be declared multiple times, categories cannot.
      Diag(CategoryLoc, diag::warn_dup_category_def)
        << ClassName << CategoryName;
      Diag(Previous->getLocation(), diag::note_previous_definition);
    }
  }

  CDecl = ObjCCategoryDecl::Create(Context, CurContext, AtInterfaceLoc,
                                   ClassLoc, CategoryLoc, CategoryName, IDecl);
  // FIXME: PushOnScopeChains?
  CurContext->addDecl(CDecl);

  if (NumProtoRefs) {
    CDecl->setProtocolList((ObjCProtocolDecl*const*)ProtoRefs, NumProtoRefs, 
                           ProtoLocs, Context);
    // Protocols in the class extension belong to the class.
    if (CDecl->IsClassExtension())
     IDecl->mergeClassExtensionProtocolList((ObjCProtocolDecl*const*)ProtoRefs, 
                                            NumProtoRefs, Context); 
  }

  CheckObjCDeclScope(CDecl);
  return ActOnObjCContainerStartDefinition(CDecl);
}

/// ActOnStartCategoryImplementation - Perform semantic checks on the
/// category implementation declaration and build an ObjCCategoryImplDecl
/// object.
Decl *Sema::ActOnStartCategoryImplementation(
                      SourceLocation AtCatImplLoc,
                      IdentifierInfo *ClassName, SourceLocation ClassLoc,
                      IdentifierInfo *CatName, SourceLocation CatLoc) {
  ObjCInterfaceDecl *IDecl = getObjCInterfaceDecl(ClassName, ClassLoc, true);
  ObjCCategoryDecl *CatIDecl = 0;
  if (IDecl && IDecl->hasDefinition()) {
    CatIDecl = IDecl->FindCategoryDeclaration(CatName);
    if (!CatIDecl) {
      // Category @implementation with no corresponding @interface.
      // Create and install one.
      CatIDecl = ObjCCategoryDecl::Create(Context, CurContext, AtCatImplLoc,
                                          ClassLoc, CatLoc,
                                          CatName, IDecl);
      CatIDecl->setImplicit();
    }
  }

  ObjCCategoryImplDecl *CDecl =
    ObjCCategoryImplDecl::Create(Context, CurContext, CatName, IDecl,
                                 ClassLoc, AtCatImplLoc, CatLoc);
  /// Check that class of this category is already completely declared.
  if (!IDecl) {
    Diag(ClassLoc, diag::err_undef_interface) << ClassName;
    CDecl->setInvalidDecl();
  } else if (RequireCompleteType(ClassLoc, Context.getObjCInterfaceType(IDecl),
                                 diag::err_undef_interface)) {
    CDecl->setInvalidDecl();
  }

  // FIXME: PushOnScopeChains?
  CurContext->addDecl(CDecl);

  // If the interface is deprecated/unavailable, warn/error about it.
  if (IDecl)
    DiagnoseUseOfDecl(IDecl, ClassLoc);

  /// Check that CatName, category name, is not used in another implementation.
  if (CatIDecl) {
    if (CatIDecl->getImplementation()) {
      Diag(ClassLoc, diag::err_dup_implementation_category) << ClassName
        << CatName;
      Diag(CatIDecl->getImplementation()->getLocation(),
           diag::note_previous_definition);
      CDecl->setInvalidDecl();
    } else {
      CatIDecl->setImplementation(CDecl);
      // Warn on implementating category of deprecated class under 
      // -Wdeprecated-implementations flag.
      DiagnoseObjCImplementedDeprecations(*this, 
                                          dyn_cast<NamedDecl>(IDecl), 
                                          CDecl->getLocation(), 2);
    }
  }

  CheckObjCDeclScope(CDecl);
  return ActOnObjCContainerStartDefinition(CDecl);
}

Decl *Sema::ActOnStartClassImplementation(
                      SourceLocation AtClassImplLoc,
                      IdentifierInfo *ClassName, SourceLocation ClassLoc,
                      IdentifierInfo *SuperClassname,
                      SourceLocation SuperClassLoc) {
  ObjCInterfaceDecl* IDecl = 0;
  // Check for another declaration kind with the same name.
  NamedDecl *PrevDecl
    = LookupSingleName(TUScope, ClassName, ClassLoc, LookupOrdinaryName,
                       ForRedeclaration);
  if (PrevDecl && !isa<ObjCInterfaceDecl>(PrevDecl)) {
    Diag(ClassLoc, diag::err_redefinition_different_kind) << ClassName;
    Diag(PrevDecl->getLocation(), diag::note_previous_definition);
  } else if ((IDecl = dyn_cast_or_null<ObjCInterfaceDecl>(PrevDecl))) {
    RequireCompleteType(ClassLoc, Context.getObjCInterfaceType(IDecl),
                        diag::warn_undef_interface);
  } else {
    // We did not find anything with the name ClassName; try to correct for 
    // typos in the class name.
    ObjCInterfaceValidatorCCC Validator;
    if (TypoCorrection Corrected = CorrectTypo(
        DeclarationNameInfo(ClassName, ClassLoc), LookupOrdinaryName, TUScope,
        NULL, Validator)) {
      // Suggest the (potentially) correct interface name. However, put the
      // fix-it hint itself in a separate note, since changing the name in 
      // the warning would make the fix-it change semantics.However, don't
      // provide a code-modification hint or use the typo name for recovery,
      // because this is just a warning. The program may actually be correct.
      IDecl = Corrected.getCorrectionDeclAs<ObjCInterfaceDecl>();
      DeclarationName CorrectedName = Corrected.getCorrection();
      Diag(ClassLoc, diag::warn_undef_interface_suggest)
        << ClassName << CorrectedName;
      Diag(IDecl->getLocation(), diag::note_previous_decl) << CorrectedName
        << FixItHint::CreateReplacement(ClassLoc, CorrectedName.getAsString());
      IDecl = 0;
    } else {
      Diag(ClassLoc, diag::warn_undef_interface) << ClassName;
    }
  }

  // Check that super class name is valid class name
  ObjCInterfaceDecl* SDecl = 0;
  if (SuperClassname) {
    // Check if a different kind of symbol declared in this scope.
    PrevDecl = LookupSingleName(TUScope, SuperClassname, SuperClassLoc,
                                LookupOrdinaryName);
    if (PrevDecl && !isa<ObjCInterfaceDecl>(PrevDecl)) {
      Diag(SuperClassLoc, diag::err_redefinition_different_kind)
        << SuperClassname;
      Diag(PrevDecl->getLocation(), diag::note_previous_definition);
    } else {
      SDecl = dyn_cast_or_null<ObjCInterfaceDecl>(PrevDecl);
      if (SDecl && !SDecl->hasDefinition())
        SDecl = 0;
      if (!SDecl)
        Diag(SuperClassLoc, diag::err_undef_superclass)
          << SuperClassname << ClassName;
      else if (IDecl && !declaresSameEntity(IDecl->getSuperClass(), SDecl)) {
        // This implementation and its interface do not have the same
        // super class.
        Diag(SuperClassLoc, diag::err_conflicting_super_class)
          << SDecl->getDeclName();
        Diag(SDecl->getLocation(), diag::note_previous_definition);
      }
    }
  }

  if (!IDecl) {
    // Legacy case of @implementation with no corresponding @interface.
    // Build, chain & install the interface decl into the identifier.

    // FIXME: Do we support attributes on the @implementation? If so we should
    // copy them over.
    IDecl = ObjCInterfaceDecl::Create(Context, CurContext, AtClassImplLoc,
                                      ClassName, /*PrevDecl=*/0, ClassLoc, 
                                      true);
    IDecl->startDefinition();
    if (SDecl) {
      IDecl->setSuperClass(SDecl);
      IDecl->setSuperClassLoc(SuperClassLoc);
      IDecl->setEndOfDefinitionLoc(SuperClassLoc);
    } else {
      IDecl->setEndOfDefinitionLoc(ClassLoc);
    }
    
    PushOnScopeChains(IDecl, TUScope);
  } else {
    // Mark the interface as being completed, even if it was just as
    //   @class ....;
    // declaration; the user cannot reopen it.
    if (!IDecl->hasDefinition())
      IDecl->startDefinition();
  }

  ObjCImplementationDecl* IMPDecl =
    ObjCImplementationDecl::Create(Context, CurContext, IDecl, SDecl,
                                   ClassLoc, AtClassImplLoc, SuperClassLoc);

  if (CheckObjCDeclScope(IMPDecl))
    return ActOnObjCContainerStartDefinition(IMPDecl);

  // Check that there is no duplicate implementation of this class.
  if (IDecl->getImplementation()) {
    // FIXME: Don't leak everything!
    Diag(ClassLoc, diag::err_dup_implementation_class) << ClassName;
    Diag(IDecl->getImplementation()->getLocation(),
         diag::note_previous_definition);
    IMPDecl->setInvalidDecl();
  } else { // add it to the list.
    IDecl->setImplementation(IMPDecl);
    PushOnScopeChains(IMPDecl, TUScope);
    // Warn on implementating deprecated class under 
    // -Wdeprecated-implementations flag.
    DiagnoseObjCImplementedDeprecations(*this, 
                                        dyn_cast<NamedDecl>(IDecl), 
                                        IMPDecl->getLocation(), 1);
  }
  return ActOnObjCContainerStartDefinition(IMPDecl);
}

Sema::DeclGroupPtrTy
Sema::ActOnFinishObjCImplementation(Decl *ObjCImpDecl, ArrayRef<Decl *> Decls) {
  SmallVector<Decl *, 64> DeclsInGroup;
  DeclsInGroup.reserve(Decls.size() + 1);

  for (unsigned i = 0, e = Decls.size(); i != e; ++i) {
    Decl *Dcl = Decls[i];
    if (!Dcl)
      continue;
    if (Dcl->getDeclContext()->isFileContext())
      Dcl->setTopLevelDeclInObjCContainer();
    DeclsInGroup.push_back(Dcl);
  }

  DeclsInGroup.push_back(ObjCImpDecl);

  return BuildDeclaratorGroup(DeclsInGroup.data(), DeclsInGroup.size(), false);
}

void Sema::CheckImplementationIvars(ObjCImplementationDecl *ImpDecl,
                                    ObjCIvarDecl **ivars, unsigned numIvars,
                                    SourceLocation RBrace) {
  assert(ImpDecl && "missing implementation decl");
  ObjCInterfaceDecl* IDecl = ImpDecl->getClassInterface();
  if (!IDecl)
    return;
  /// Check case of non-existing \@interface decl.
  /// (legacy objective-c \@implementation decl without an \@interface decl).
  /// Add implementations's ivar to the synthesize class's ivar list.
  if (IDecl->isImplicitInterfaceDecl()) {
    IDecl->setEndOfDefinitionLoc(RBrace);
    // Add ivar's to class's DeclContext.
    for (unsigned i = 0, e = numIvars; i != e; ++i) {
      ivars[i]->setLexicalDeclContext(ImpDecl);
      IDecl->makeDeclVisibleInContext(ivars[i]);
      ImpDecl->addDecl(ivars[i]);
    }
    
    return;
  }
  // If implementation has empty ivar list, just return.
  if (numIvars == 0)
    return;

  assert(ivars && "missing @implementation ivars");
  if (LangOpts.ObjCRuntime.isNonFragile()) {
    if (ImpDecl->getSuperClass())
      Diag(ImpDecl->getLocation(), diag::warn_on_superclass_use);
    for (unsigned i = 0; i < numIvars; i++) {
      ObjCIvarDecl* ImplIvar = ivars[i];
      if (const ObjCIvarDecl *ClsIvar = 
            IDecl->getIvarDecl(ImplIvar->getIdentifier())) {
        Diag(ImplIvar->getLocation(), diag::err_duplicate_ivar_declaration); 
        Diag(ClsIvar->getLocation(), diag::note_previous_definition);
        continue;
      }
      // Instance ivar to Implementation's DeclContext.
      ImplIvar->setLexicalDeclContext(ImpDecl);
      IDecl->makeDeclVisibleInContext(ImplIvar);
      ImpDecl->addDecl(ImplIvar);
    }
    return;
  }
  // Check interface's Ivar list against those in the implementation.
  // names and types must match.
  //
  unsigned j = 0;
  ObjCInterfaceDecl::ivar_iterator
    IVI = IDecl->ivar_begin(), IVE = IDecl->ivar_end();
  for (; numIvars > 0 && IVI != IVE; ++IVI) {
    ObjCIvarDecl* ImplIvar = ivars[j++];
    ObjCIvarDecl* ClsIvar = *IVI;
    assert (ImplIvar && "missing implementation ivar");
    assert (ClsIvar && "missing class ivar");

    // First, make sure the types match.
    if (!Context.hasSameType(ImplIvar->getType(), ClsIvar->getType())) {
      Diag(ImplIvar->getLocation(), diag::err_conflicting_ivar_type)
        << ImplIvar->getIdentifier()
        << ImplIvar->getType() << ClsIvar->getType();
      Diag(ClsIvar->getLocation(), diag::note_previous_definition);
    } else if (ImplIvar->isBitField() && ClsIvar->isBitField() &&
               ImplIvar->getBitWidthValue(Context) !=
               ClsIvar->getBitWidthValue(Context)) {
      Diag(ImplIvar->getBitWidth()->getLocStart(),
           diag::err_conflicting_ivar_bitwidth) << ImplIvar->getIdentifier();
      Diag(ClsIvar->getBitWidth()->getLocStart(),
           diag::note_previous_definition);
    }
    // Make sure the names are identical.
    if (ImplIvar->getIdentifier() != ClsIvar->getIdentifier()) {
      Diag(ImplIvar->getLocation(), diag::err_conflicting_ivar_name)
        << ImplIvar->getIdentifier() << ClsIvar->getIdentifier();
      Diag(ClsIvar->getLocation(), diag::note_previous_definition);
    }
    --numIvars;
  }

  if (numIvars > 0)
    Diag(ivars[j]->getLocation(), diag::err_inconsistant_ivar_count);
  else if (IVI != IVE)
    Diag(IVI->getLocation(), diag::err_inconsistant_ivar_count);
}

void Sema::WarnUndefinedMethod(SourceLocation ImpLoc, ObjCMethodDecl *method,
                               bool &IncompleteImpl, unsigned DiagID) {
  // No point warning no definition of method which is 'unavailable'.
  switch (method->getAvailability()) {
  case AR_Available:
  case AR_Deprecated:
    break;

      // Don't warn about unavailable or not-yet-introduced methods.
  case AR_NotYetIntroduced:
  case AR_Unavailable:
    return;
  }
  
  // FIXME: For now ignore 'IncompleteImpl'.
  // Previously we grouped all unimplemented methods under a single
  // warning, but some users strongly voiced that they would prefer
  // separate warnings.  We will give that approach a try, as that
  // matches what we do with protocols.
  
  Diag(ImpLoc, DiagID) << method->getDeclName();

  // Issue a note to the original declaration.
  SourceLocation MethodLoc = method->getLocStart();
  if (MethodLoc.isValid())
    Diag(MethodLoc, diag::note_method_declared_at) << method;
}

/// Determines if type B can be substituted for type A.  Returns true if we can
/// guarantee that anything that the user will do to an object of type A can 
/// also be done to an object of type B.  This is trivially true if the two 
/// types are the same, or if B is a subclass of A.  It becomes more complex
/// in cases where protocols are involved.
///
/// Object types in Objective-C describe the minimum requirements for an
/// object, rather than providing a complete description of a type.  For
/// example, if A is a subclass of B, then B* may refer to an instance of A.
/// The principle of substitutability means that we may use an instance of A
/// anywhere that we may use an instance of B - it will implement all of the
/// ivars of B and all of the methods of B.  
///
/// This substitutability is important when type checking methods, because 
/// the implementation may have stricter type definitions than the interface.
/// The interface specifies minimum requirements, but the implementation may
/// have more accurate ones.  For example, a method may privately accept 
/// instances of B, but only publish that it accepts instances of A.  Any
/// object passed to it will be type checked against B, and so will implicitly
/// by a valid A*.  Similarly, a method may return a subclass of the class that
/// it is declared as returning.
///
/// This is most important when considering subclassing.  A method in a
/// subclass must accept any object as an argument that its superclass's
/// implementation accepts.  It may, however, accept a more general type
/// without breaking substitutability (i.e. you can still use the subclass
/// anywhere that you can use the superclass, but not vice versa).  The
/// converse requirement applies to return types: the return type for a
/// subclass method must be a valid object of the kind that the superclass
/// advertises, but it may be specified more accurately.  This avoids the need
/// for explicit down-casting by callers.
///
/// Note: This is a stricter requirement than for assignment.  
static bool isObjCTypeSubstitutable(ASTContext &Context,
                                    const ObjCObjectPointerType *A,
                                    const ObjCObjectPointerType *B,
                                    bool rejectId) {
  // Reject a protocol-unqualified id.
  if (rejectId && B->isObjCIdType()) return false;

  // If B is a qualified id, then A must also be a qualified id and it must
  // implement all of the protocols in B.  It may not be a qualified class.
  // For example, MyClass<A> can be assigned to id<A>, but MyClass<A> is a
  // stricter definition so it is not substitutable for id<A>.
  if (B->isObjCQualifiedIdType()) {
    return A->isObjCQualifiedIdType() &&
           Context.ObjCQualifiedIdTypesAreCompatible(QualType(A, 0),
                                                     QualType(B,0),
                                                     false);
  }

  /*
  // id is a special type that bypasses type checking completely.  We want a
  // warning when it is used in one place but not another.
  if (C.isObjCIdType(A) || C.isObjCIdType(B)) return false;


  // If B is a qualified id, then A must also be a qualified id (which it isn't
  // if we've got this far)
  if (B->isObjCQualifiedIdType()) return false;
  */

  // Now we know that A and B are (potentially-qualified) class types.  The
  // normal rules for assignment apply.
  return Context.canAssignObjCInterfaces(A, B);
}

static SourceRange getTypeRange(TypeSourceInfo *TSI) {
  return (TSI ? TSI->getTypeLoc().getSourceRange() : SourceRange());
}

static bool CheckMethodOverrideReturn(Sema &S,
                                      ObjCMethodDecl *MethodImpl,
                                      ObjCMethodDecl *MethodDecl,
                                      bool IsProtocolMethodDecl,
                                      bool IsOverridingMode,
                                      bool Warn) {
  if (IsProtocolMethodDecl &&
      (MethodDecl->getObjCDeclQualifier() !=
       MethodImpl->getObjCDeclQualifier())) {
    if (Warn) {
        S.Diag(MethodImpl->getLocation(), 
               (IsOverridingMode ? 
                 diag::warn_conflicting_overriding_ret_type_modifiers 
                 : diag::warn_conflicting_ret_type_modifiers))
          << MethodImpl->getDeclName()
          << getTypeRange(MethodImpl->getResultTypeSourceInfo());
        S.Diag(MethodDecl->getLocation(), diag::note_previous_declaration)
          << getTypeRange(MethodDecl->getResultTypeSourceInfo());
    }
    else
      return false;
  }
  
  if (S.Context.hasSameUnqualifiedType(MethodImpl->getResultType(),
                                       MethodDecl->getResultType()))
    return true;
  if (!Warn)
    return false;

  unsigned DiagID = 
    IsOverridingMode ? diag::warn_conflicting_overriding_ret_types 
                     : diag::warn_conflicting_ret_types;

  // Mismatches between ObjC pointers go into a different warning
  // category, and sometimes they're even completely whitelisted.
  if (const ObjCObjectPointerType *ImplPtrTy =
        MethodImpl->getResultType()->getAs<ObjCObjectPointerType>()) {
    if (const ObjCObjectPointerType *IfacePtrTy =
          MethodDecl->getResultType()->getAs<ObjCObjectPointerType>()) {
      // Allow non-matching return types as long as they don't violate
      // the principle of substitutability.  Specifically, we permit
      // return types that are subclasses of the declared return type,
      // or that are more-qualified versions of the declared type.
      if (isObjCTypeSubstitutable(S.Context, IfacePtrTy, ImplPtrTy, false))
        return false;

      DiagID = 
        IsOverridingMode ? diag::warn_non_covariant_overriding_ret_types 
                          : diag::warn_non_covariant_ret_types;
    }
  }

  S.Diag(MethodImpl->getLocation(), DiagID)
    << MethodImpl->getDeclName()
    << MethodDecl->getResultType()
    << MethodImpl->getResultType()
    << getTypeRange(MethodImpl->getResultTypeSourceInfo());
  S.Diag(MethodDecl->getLocation(), 
         IsOverridingMode ? diag::note_previous_declaration 
                          : diag::note_previous_definition)
    << getTypeRange(MethodDecl->getResultTypeSourceInfo());
  return false;
}

static bool CheckMethodOverrideParam(Sema &S,
                                     ObjCMethodDecl *MethodImpl,
                                     ObjCMethodDecl *MethodDecl,
                                     ParmVarDecl *ImplVar,
                                     ParmVarDecl *IfaceVar,
                                     bool IsProtocolMethodDecl,
                                     bool IsOverridingMode,
                                     bool Warn) {
  if (IsProtocolMethodDecl &&
      (ImplVar->getObjCDeclQualifier() !=
       IfaceVar->getObjCDeclQualifier())) {
    if (Warn) {
      if (IsOverridingMode)
        S.Diag(ImplVar->getLocation(), 
               diag::warn_conflicting_overriding_param_modifiers)
            << getTypeRange(ImplVar->getTypeSourceInfo())
            << MethodImpl->getDeclName();
      else S.Diag(ImplVar->getLocation(), 
             diag::warn_conflicting_param_modifiers)
          << getTypeRange(ImplVar->getTypeSourceInfo())
          << MethodImpl->getDeclName();
      S.Diag(IfaceVar->getLocation(), diag::note_previous_declaration)
          << getTypeRange(IfaceVar->getTypeSourceInfo());   
    }
    else
      return false;
  }
      
  QualType ImplTy = ImplVar->getType();
  QualType IfaceTy = IfaceVar->getType();
  
  if (S.Context.hasSameUnqualifiedType(ImplTy, IfaceTy))
    return true;
  
  if (!Warn)
    return false;
  unsigned DiagID = 
    IsOverridingMode ? diag::warn_conflicting_overriding_param_types 
                     : diag::warn_conflicting_param_types;

  // Mismatches between ObjC pointers go into a different warning
  // category, and sometimes they're even completely whitelisted.
  if (const ObjCObjectPointerType *ImplPtrTy =
        ImplTy->getAs<ObjCObjectPointerType>()) {
    if (const ObjCObjectPointerType *IfacePtrTy =
          IfaceTy->getAs<ObjCObjectPointerType>()) {
      // Allow non-matching argument types as long as they don't
      // violate the principle of substitutability.  Specifically, the
      // implementation must accept any objects that the superclass
      // accepts, however it may also accept others.
      if (isObjCTypeSubstitutable(S.Context, ImplPtrTy, IfacePtrTy, true))
        return false;

      DiagID = 
      IsOverridingMode ? diag::warn_non_contravariant_overriding_param_types 
                       :  diag::warn_non_contravariant_param_types;
    }
  }

  S.Diag(ImplVar->getLocation(), DiagID)
    << getTypeRange(ImplVar->getTypeSourceInfo())
    << MethodImpl->getDeclName() << IfaceTy << ImplTy;
  S.Diag(IfaceVar->getLocation(), 
         (IsOverridingMode ? diag::note_previous_declaration 
                        : diag::note_previous_definition))
    << getTypeRange(IfaceVar->getTypeSourceInfo());
  return false;
}

/// In ARC, check whether the conventional meanings of the two methods
/// match.  If they don't, it's a hard error.
static bool checkMethodFamilyMismatch(Sema &S, ObjCMethodDecl *impl,
                                      ObjCMethodDecl *decl) {
  ObjCMethodFamily implFamily = impl->getMethodFamily();
  ObjCMethodFamily declFamily = decl->getMethodFamily();
  if (implFamily == declFamily) return false;

  // Since conventions are sorted by selector, the only possibility is
  // that the types differ enough to cause one selector or the other
  // to fall out of the family.
  assert(implFamily == OMF_None || declFamily == OMF_None);

  // No further diagnostics required on invalid declarations.
  if (impl->isInvalidDecl() || decl->isInvalidDecl()) return true;

  const ObjCMethodDecl *unmatched = impl;
  ObjCMethodFamily family = declFamily;
  unsigned errorID = diag::err_arc_lost_method_convention;
  unsigned noteID = diag::note_arc_lost_method_convention;
  if (declFamily == OMF_None) {
    unmatched = decl;
    family = implFamily;
    errorID = diag::err_arc_gained_method_convention;
    noteID = diag::note_arc_gained_method_convention;
  }

  // Indexes into a %select clause in the diagnostic.
  enum FamilySelector {
    F_alloc, F_copy, F_mutableCopy = F_copy, F_init, F_new
  };
  FamilySelector familySelector = FamilySelector();

  switch (family) {
  case OMF_None: llvm_unreachable("logic error, no method convention");
  case OMF_retain:
  case OMF_release:
  case OMF_autorelease:
  case OMF_dealloc:
  case OMF_finalize:
  case OMF_retainCount:
  case OMF_self:
  case OMF_performSelector:
    // Mismatches for these methods don't change ownership
    // conventions, so we don't care.
    return false;

  case OMF_init: familySelector = F_init; break;
  case OMF_alloc: familySelector = F_alloc; break;
  case OMF_copy: familySelector = F_copy; break;
  case OMF_mutableCopy: familySelector = F_mutableCopy; break;
  case OMF_new: familySelector = F_new; break;
  }

  enum ReasonSelector { R_NonObjectReturn, R_UnrelatedReturn };
  ReasonSelector reasonSelector;

  // The only reason these methods don't fall within their families is
  // due to unusual result types.
  if (unmatched->getResultType()->isObjCObjectPointerType()) {
    reasonSelector = R_UnrelatedReturn;
  } else {
    reasonSelector = R_NonObjectReturn;
  }

  S.Diag(impl->getLocation(), errorID) << familySelector << reasonSelector;
  S.Diag(decl->getLocation(), noteID) << familySelector << reasonSelector;

  return true;
}

void Sema::WarnConflictingTypedMethods(ObjCMethodDecl *ImpMethodDecl,
                                       ObjCMethodDecl *MethodDecl,
                                       bool IsProtocolMethodDecl) {
  if (getLangOpts().ObjCAutoRefCount &&
      checkMethodFamilyMismatch(*this, ImpMethodDecl, MethodDecl))
    return;

  CheckMethodOverrideReturn(*this, ImpMethodDecl, MethodDecl, 
                            IsProtocolMethodDecl, false, 
                            true);

  for (ObjCMethodDecl::param_iterator IM = ImpMethodDecl->param_begin(),
       IF = MethodDecl->param_begin(), EM = ImpMethodDecl->param_end(),
       EF = MethodDecl->param_end();
       IM != EM && IF != EF; ++IM, ++IF) {
    CheckMethodOverrideParam(*this, ImpMethodDecl, MethodDecl, *IM, *IF,
                             IsProtocolMethodDecl, false, true);
  }

  if (ImpMethodDecl->isVariadic() != MethodDecl->isVariadic()) {
    Diag(ImpMethodDecl->getLocation(), 
         diag::warn_conflicting_variadic);
    Diag(MethodDecl->getLocation(), diag::note_previous_declaration);
  }
}

void Sema::CheckConflictingOverridingMethod(ObjCMethodDecl *Method,
                                       ObjCMethodDecl *Overridden,
                                       bool IsProtocolMethodDecl) {
  
  CheckMethodOverrideReturn(*this, Method, Overridden, 
                            IsProtocolMethodDecl, true, 
                            true);
  
  for (ObjCMethodDecl::param_iterator IM = Method->param_begin(),
       IF = Overridden->param_begin(), EM = Method->param_end(),
       EF = Overridden->param_end();
       IM != EM && IF != EF; ++IM, ++IF) {
    CheckMethodOverrideParam(*this, Method, Overridden, *IM, *IF,
                             IsProtocolMethodDecl, true, true);
  }
  
  if (Method->isVariadic() != Overridden->isVariadic()) {
    Diag(Method->getLocation(), 
         diag::warn_conflicting_overriding_variadic);
    Diag(Overridden->getLocation(), diag::note_previous_declaration);
  }
}

/// WarnExactTypedMethods - This routine issues a warning if method
/// implementation declaration matches exactly that of its declaration.
void Sema::WarnExactTypedMethods(ObjCMethodDecl *ImpMethodDecl,
                                 ObjCMethodDecl *MethodDecl,
                                 bool IsProtocolMethodDecl) {
  // don't issue warning when protocol method is optional because primary
  // class is not required to implement it and it is safe for protocol
  // to implement it.
  if (MethodDecl->getImplementationControl() == ObjCMethodDecl::Optional)
    return;
  // don't issue warning when primary class's method is 
  // depecated/unavailable.
  if (MethodDecl->hasAttr<UnavailableAttr>() ||
      MethodDecl->hasAttr<DeprecatedAttr>())
    return;
  
  bool match = CheckMethodOverrideReturn(*this, ImpMethodDecl, MethodDecl, 
                                      IsProtocolMethodDecl, false, false);
  if (match)
    for (ObjCMethodDecl::param_iterator IM = ImpMethodDecl->param_begin(),
         IF = MethodDecl->param_begin(), EM = ImpMethodDecl->param_end(),
         EF = MethodDecl->param_end();
         IM != EM && IF != EF; ++IM, ++IF) {
      match = CheckMethodOverrideParam(*this, ImpMethodDecl, MethodDecl, 
                                       *IM, *IF,
                                       IsProtocolMethodDecl, false, false);
      if (!match)
        break;
    }
  if (match)
    match = (ImpMethodDecl->isVariadic() == MethodDecl->isVariadic());
  if (match)
    match = !(MethodDecl->isClassMethod() &&
              MethodDecl->getSelector() == GetNullarySelector("load", Context));
  
  if (match) {
    Diag(ImpMethodDecl->getLocation(), 
         diag::warn_category_method_impl_match);
    Diag(MethodDecl->getLocation(), diag::note_method_declared_at)
      << MethodDecl->getDeclName();
  }
}

/// FIXME: Type hierarchies in Objective-C can be deep. We could most likely
/// improve the efficiency of selector lookups and type checking by associating
/// with each protocol / interface / category the flattened instance tables. If
/// we used an immutable set to keep the table then it wouldn't add significant
/// memory cost and it would be handy for lookups.

/// CheckProtocolMethodDefs - This routine checks unimplemented methods
/// Declared in protocol, and those referenced by it.
void Sema::CheckProtocolMethodDefs(SourceLocation ImpLoc,
                                   ObjCProtocolDecl *PDecl,
                                   bool& IncompleteImpl,
                                   const SelectorSet &InsMap,
                                   const SelectorSet &ClsMap,
                                   ObjCContainerDecl *CDecl) {
  ObjCCategoryDecl *C = dyn_cast<ObjCCategoryDecl>(CDecl);
  ObjCInterfaceDecl *IDecl = C ? C->getClassInterface() 
                               : dyn_cast<ObjCInterfaceDecl>(CDecl);
  assert (IDecl && "CheckProtocolMethodDefs - IDecl is null");
  
  ObjCInterfaceDecl *Super = IDecl->getSuperClass();
  ObjCInterfaceDecl *NSIDecl = 0;
  if (getLangOpts().ObjCRuntime.isNeXTFamily()) {
    // check to see if class implements forwardInvocation method and objects
    // of this class are derived from 'NSProxy' so that to forward requests
    // from one object to another.
    // Under such conditions, which means that every method possible is
    // implemented in the class, we should not issue "Method definition not
    // found" warnings.
    // FIXME: Use a general GetUnarySelector method for this.
    IdentifierInfo* II = &Context.Idents.get("forwardInvocation");
    Selector fISelector = Context.Selectors.getSelector(1, &II);
    if (InsMap.count(fISelector))
      // Is IDecl derived from 'NSProxy'? If so, no instance methods
      // need be implemented in the implementation.
      NSIDecl = IDecl->lookupInheritedClass(&Context.Idents.get("NSProxy"));
  }

  // If this is a forward protocol declaration, get its definition.
  if (!PDecl->isThisDeclarationADefinition() &&
      PDecl->getDefinition())
    PDecl = PDecl->getDefinition();
  
  // If a method lookup fails locally we still need to look and see if
  // the method was implemented by a base class or an inherited
  // protocol. This lookup is slow, but occurs rarely in correct code
  // and otherwise would terminate in a warning.

  // check unimplemented instance methods.
  if (!NSIDecl)
    for (ObjCProtocolDecl::instmeth_iterator I = PDecl->instmeth_begin(),
         E = PDecl->instmeth_end(); I != E; ++I) {
      ObjCMethodDecl *method = *I;
      if (method->getImplementationControl() != ObjCMethodDecl::Optional &&
          !method->isPropertyAccessor() &&
          !InsMap.count(method->getSelector()) &&
          (!Super || !Super->lookupInstanceMethod(method->getSelector()))) {
            // If a method is not implemented in the category implementation but
            // has been declared in its primary class, superclass,
            // or in one of their protocols, no need to issue the warning. 
            // This is because method will be implemented in the primary class 
            // or one of its super class implementation.
            
            // Ugly, but necessary. Method declared in protcol might have
            // have been synthesized due to a property declared in the class which
            // uses the protocol.
            if (ObjCMethodDecl *MethodInClass =
                  IDecl->lookupInstanceMethod(method->getSelector(), 
                                              true /*shallowCategoryLookup*/))
              if (C || MethodInClass->isPropertyAccessor())
                continue;
            unsigned DIAG = diag::warn_unimplemented_protocol_method;
            if (Diags.getDiagnosticLevel(DIAG, ImpLoc)
                != DiagnosticsEngine::Ignored) {
              WarnUndefinedMethod(ImpLoc, method, IncompleteImpl, DIAG);
              Diag(CDecl->getLocation(), diag::note_required_for_protocol_at)
                << PDecl->getDeclName();
            }
          }
    }
  // check unimplemented class methods
  for (ObjCProtocolDecl::classmeth_iterator
         I = PDecl->classmeth_begin(), E = PDecl->classmeth_end();
       I != E; ++I) {
    ObjCMethodDecl *method = *I;
    if (method->getImplementationControl() != ObjCMethodDecl::Optional &&
        !ClsMap.count(method->getSelector()) &&
        (!Super || !Super->lookupClassMethod(method->getSelector()))) {
      // See above comment for instance method lookups.
      if (C && IDecl->lookupClassMethod(method->getSelector(), 
                                        true /*shallowCategoryLookup*/))
        continue;
      unsigned DIAG = diag::warn_unimplemented_protocol_method;
      if (Diags.getDiagnosticLevel(DIAG, ImpLoc) !=
            DiagnosticsEngine::Ignored) {
        WarnUndefinedMethod(ImpLoc, method, IncompleteImpl, DIAG);
        Diag(IDecl->getLocation(), diag::note_required_for_protocol_at) <<
          PDecl->getDeclName();
      }
    }
  }
  // Check on this protocols's referenced protocols, recursively.
  for (ObjCProtocolDecl::protocol_iterator PI = PDecl->protocol_begin(),
       E = PDecl->protocol_end(); PI != E; ++PI)
    CheckProtocolMethodDefs(ImpLoc, *PI, IncompleteImpl, InsMap, ClsMap, CDecl);
}

/// MatchAllMethodDeclarations - Check methods declared in interface
/// or protocol against those declared in their implementations.
///
void Sema::MatchAllMethodDeclarations(const SelectorSet &InsMap,
                                      const SelectorSet &ClsMap,
                                      SelectorSet &InsMapSeen,
                                      SelectorSet &ClsMapSeen,
                                      ObjCImplDecl* IMPDecl,
                                      ObjCContainerDecl* CDecl,
                                      bool &IncompleteImpl,
                                      bool ImmediateClass,
                                      bool WarnCategoryMethodImpl) {
  // Check and see if instance methods in class interface have been
  // implemented in the implementation class. If so, their types match.
  for (ObjCInterfaceDecl::instmeth_iterator I = CDecl->instmeth_begin(),
       E = CDecl->instmeth_end(); I != E; ++I) {
    if (InsMapSeen.count((*I)->getSelector()))
        continue;
    InsMapSeen.insert((*I)->getSelector());
    if (!(*I)->isPropertyAccessor() &&
        !InsMap.count((*I)->getSelector())) {
      if (ImmediateClass)
        WarnUndefinedMethod(IMPDecl->getLocation(), *I, IncompleteImpl,
                            diag::warn_undef_method_impl);
      continue;
    } else {
      ObjCMethodDecl *ImpMethodDecl =
        IMPDecl->getInstanceMethod((*I)->getSelector());
      assert(CDecl->getInstanceMethod((*I)->getSelector()) &&
             "Expected to find the method through lookup as well");
      ObjCMethodDecl *MethodDecl = *I;
      // ImpMethodDecl may be null as in a @dynamic property.
      if (ImpMethodDecl) {
        if (!WarnCategoryMethodImpl)
          WarnConflictingTypedMethods(ImpMethodDecl, MethodDecl,
                                      isa<ObjCProtocolDecl>(CDecl));
        else if (!MethodDecl->isPropertyAccessor())
          WarnExactTypedMethods(ImpMethodDecl, MethodDecl,
                                isa<ObjCProtocolDecl>(CDecl));
      }
    }
  }

  // Check and see if class methods in class interface have been
  // implemented in the implementation class. If so, their types match.
   for (ObjCInterfaceDecl::classmeth_iterator
       I = CDecl->classmeth_begin(), E = CDecl->classmeth_end(); I != E; ++I) {
     if (ClsMapSeen.count((*I)->getSelector()))
       continue;
     ClsMapSeen.insert((*I)->getSelector());
    if (!ClsMap.count((*I)->getSelector())) {
      if (ImmediateClass)
        WarnUndefinedMethod(IMPDecl->getLocation(), *I, IncompleteImpl,
                            diag::warn_undef_method_impl);
    } else {
      ObjCMethodDecl *ImpMethodDecl =
        IMPDecl->getClassMethod((*I)->getSelector());
      assert(CDecl->getClassMethod((*I)->getSelector()) &&
             "Expected to find the method through lookup as well");
      ObjCMethodDecl *MethodDecl = *I;
      if (!WarnCategoryMethodImpl)
        WarnConflictingTypedMethods(ImpMethodDecl, MethodDecl, 
                                    isa<ObjCProtocolDecl>(CDecl));
      else
        WarnExactTypedMethods(ImpMethodDecl, MethodDecl,
                              isa<ObjCProtocolDecl>(CDecl));
    }
  }
  
  if (ObjCInterfaceDecl *I = dyn_cast<ObjCInterfaceDecl> (CDecl)) {
    // when checking that methods in implementation match their declaration,
    // i.e. when WarnCategoryMethodImpl is false, check declarations in class
    // extension; as well as those in categories.
    if (!WarnCategoryMethodImpl) {
      for (ObjCInterfaceDecl::visible_categories_iterator
             Cat = I->visible_categories_begin(),
           CatEnd = I->visible_categories_end();
           Cat != CatEnd; ++Cat) {
        MatchAllMethodDeclarations(InsMap, ClsMap, InsMapSeen, ClsMapSeen,
                                   IMPDecl, *Cat, IncompleteImpl, false,
                                   WarnCategoryMethodImpl);
      }
    } else {
      // Also methods in class extensions need be looked at next.
      for (ObjCInterfaceDecl::visible_extensions_iterator
             Ext = I->visible_extensions_begin(),
             ExtEnd = I->visible_extensions_end();
           Ext != ExtEnd; ++Ext) {
        MatchAllMethodDeclarations(InsMap, ClsMap, InsMapSeen, ClsMapSeen,
                                   IMPDecl, *Ext, IncompleteImpl, false,
                                   WarnCategoryMethodImpl);
      }
    }

    // Check for any implementation of a methods declared in protocol.
    for (ObjCInterfaceDecl::all_protocol_iterator
          PI = I->all_referenced_protocol_begin(),
          E = I->all_referenced_protocol_end(); PI != E; ++PI)
      MatchAllMethodDeclarations(InsMap, ClsMap, InsMapSeen, ClsMapSeen,
                                 IMPDecl,
                                 (*PI), IncompleteImpl, false, 
                                 WarnCategoryMethodImpl);
    
    // FIXME. For now, we are not checking for extact match of methods 
    // in category implementation and its primary class's super class. 
    if (!WarnCategoryMethodImpl && I->getSuperClass())
      MatchAllMethodDeclarations(InsMap, ClsMap, InsMapSeen, ClsMapSeen,
                                 IMPDecl,
                                 I->getSuperClass(), IncompleteImpl, false);
  }
}

/// CheckCategoryVsClassMethodMatches - Checks that methods implemented in
/// category matches with those implemented in its primary class and
/// warns each time an exact match is found. 
void Sema::CheckCategoryVsClassMethodMatches(
                                  ObjCCategoryImplDecl *CatIMPDecl) {
  SelectorSet InsMap, ClsMap;
  
  for (ObjCImplementationDecl::instmeth_iterator
       I = CatIMPDecl->instmeth_begin(), 
       E = CatIMPDecl->instmeth_end(); I!=E; ++I)
    InsMap.insert((*I)->getSelector());
  
  for (ObjCImplementationDecl::classmeth_iterator
       I = CatIMPDecl->classmeth_begin(),
       E = CatIMPDecl->classmeth_end(); I != E; ++I)
    ClsMap.insert((*I)->getSelector());
  if (InsMap.empty() && ClsMap.empty())
    return;
  
  // Get category's primary class.
  ObjCCategoryDecl *CatDecl = CatIMPDecl->getCategoryDecl();
  if (!CatDecl)
    return;
  ObjCInterfaceDecl *IDecl = CatDecl->getClassInterface();
  if (!IDecl)
    return;
  SelectorSet InsMapSeen, ClsMapSeen;
  bool IncompleteImpl = false;
  MatchAllMethodDeclarations(InsMap, ClsMap, InsMapSeen, ClsMapSeen,
                             CatIMPDecl, IDecl,
                             IncompleteImpl, false, 
                             true /*WarnCategoryMethodImpl*/);
}

void Sema::ImplMethodsVsClassMethods(Scope *S, ObjCImplDecl* IMPDecl,
                                     ObjCContainerDecl* CDecl,
                                     bool IncompleteImpl) {
  SelectorSet InsMap;
  // Check and see if instance methods in class interface have been
  // implemented in the implementation class.
  for (ObjCImplementationDecl::instmeth_iterator
         I = IMPDecl->instmeth_begin(), E = IMPDecl->instmeth_end(); I!=E; ++I)
    InsMap.insert((*I)->getSelector());

  // Check and see if properties declared in the interface have either 1)
  // an implementation or 2) there is a @synthesize/@dynamic implementation
  // of the property in the @implementation.
  if (const ObjCInterfaceDecl *IDecl = dyn_cast<ObjCInterfaceDecl>(CDecl))
    if  (!(LangOpts.ObjCDefaultSynthProperties &&
           LangOpts.ObjCRuntime.isNonFragile()) ||
         IDecl->isObjCRequiresPropertyDefs())
      DiagnoseUnimplementedProperties(S, IMPDecl, CDecl);
      
  SelectorSet ClsMap;
  for (ObjCImplementationDecl::classmeth_iterator
       I = IMPDecl->classmeth_begin(),
       E = IMPDecl->classmeth_end(); I != E; ++I)
    ClsMap.insert((*I)->getSelector());

  // Check for type conflict of methods declared in a class/protocol and
  // its implementation; if any.
  SelectorSet InsMapSeen, ClsMapSeen;
  MatchAllMethodDeclarations(InsMap, ClsMap, InsMapSeen, ClsMapSeen,
                             IMPDecl, CDecl,
                             IncompleteImpl, true);
  
  // check all methods implemented in category against those declared
  // in its primary class.
  if (ObjCCategoryImplDecl *CatDecl = 
        dyn_cast<ObjCCategoryImplDecl>(IMPDecl))
    CheckCategoryVsClassMethodMatches(CatDecl);

  // Check the protocol list for unimplemented methods in the @implementation
  // class.
  // Check and see if class methods in class interface have been
  // implemented in the implementation class.

  if (ObjCInterfaceDecl *I = dyn_cast<ObjCInterfaceDecl> (CDecl)) {
    for (ObjCInterfaceDecl::all_protocol_iterator
          PI = I->all_referenced_protocol_begin(),
          E = I->all_referenced_protocol_end(); PI != E; ++PI)
      CheckProtocolMethodDefs(IMPDecl->getLocation(), *PI, IncompleteImpl,
                              InsMap, ClsMap, I);
    // Check class extensions (unnamed categories)
    for (ObjCInterfaceDecl::visible_extensions_iterator
           Ext = I->visible_extensions_begin(),
           ExtEnd = I->visible_extensions_end();
         Ext != ExtEnd; ++Ext) {
      ImplMethodsVsClassMethods(S, IMPDecl, *Ext, IncompleteImpl);
    }
  } else if (ObjCCategoryDecl *C = dyn_cast<ObjCCategoryDecl>(CDecl)) {
    // For extended class, unimplemented methods in its protocols will
    // be reported in the primary class.
    if (!C->IsClassExtension()) {
      for (ObjCCategoryDecl::protocol_iterator PI = C->protocol_begin(),
           E = C->protocol_end(); PI != E; ++PI)
        CheckProtocolMethodDefs(IMPDecl->getLocation(), *PI, IncompleteImpl,
                                InsMap, ClsMap, CDecl);
      DiagnoseUnimplementedProperties(S, IMPDecl, CDecl);
    } 
  } else
    llvm_unreachable("invalid ObjCContainerDecl type.");
}

/// ActOnForwardClassDeclaration -
Sema::DeclGroupPtrTy
Sema::ActOnForwardClassDeclaration(SourceLocation AtClassLoc,
                                   IdentifierInfo **IdentList,
                                   SourceLocation *IdentLocs,
                                   unsigned NumElts) {
  SmallVector<Decl *, 8> DeclsInGroup;
  for (unsigned i = 0; i != NumElts; ++i) {
    // Check for another declaration kind with the same name.
    NamedDecl *PrevDecl
      = LookupSingleName(TUScope, IdentList[i], IdentLocs[i], 
                         LookupOrdinaryName, ForRedeclaration);
    if (PrevDecl && !isa<ObjCInterfaceDecl>(PrevDecl)) {
      // GCC apparently allows the following idiom:
      //
      // typedef NSObject < XCElementTogglerP > XCElementToggler;
      // @class XCElementToggler;
      //
      // Here we have chosen to ignore the forward class declaration
      // with a warning. Since this is the implied behavior.
      TypedefNameDecl *TDD = dyn_cast<TypedefNameDecl>(PrevDecl);
      if (!TDD || !TDD->getUnderlyingType()->isObjCObjectType()) {
        Diag(AtClassLoc, diag::err_redefinition_different_kind) << IdentList[i];
        Diag(PrevDecl->getLocation(), diag::note_previous_definition);
      } else {
        // a forward class declaration matching a typedef name of a class refers
        // to the underlying class. Just ignore the forward class with a warning
        // as this will force the intended behavior which is to lookup the typedef
        // name.
        if (isa<ObjCObjectType>(TDD->getUnderlyingType())) {
          Diag(AtClassLoc, diag::warn_forward_class_redefinition) << IdentList[i];
          Diag(PrevDecl->getLocation(), diag::note_previous_definition);
          continue;
        }
      }
    }
    
    // Create a declaration to describe this forward declaration.
    ObjCInterfaceDecl *PrevIDecl
      = dyn_cast_or_null<ObjCInterfaceDecl>(PrevDecl);

    IdentifierInfo *ClassName = IdentList[i];
    if (PrevIDecl && PrevIDecl->getIdentifier() != ClassName) {
      // A previous decl with a different name is because of
      // @compatibility_alias, for example:
      // \code
      //   @class NewImage;
      //   @compatibility_alias OldImage NewImage;
      // \endcode
      // A lookup for 'OldImage' will return the 'NewImage' decl.
      //
      // In such a case use the real declaration name, instead of the alias one,
      // otherwise we will break IdentifierResolver and redecls-chain invariants.
      // FIXME: If necessary, add a bit to indicate that this ObjCInterfaceDecl
      // has been aliased.
      ClassName = PrevIDecl->getIdentifier();
    }

    ObjCInterfaceDecl *IDecl
      = ObjCInterfaceDecl::Create(Context, CurContext, AtClassLoc,
                                  ClassName, PrevIDecl, IdentLocs[i]);
    IDecl->setAtEndRange(IdentLocs[i]);
    
    PushOnScopeChains(IDecl, TUScope);
    CheckObjCDeclScope(IDecl);
    DeclsInGroup.push_back(IDecl);
  }
  
  return BuildDeclaratorGroup(DeclsInGroup.data(), DeclsInGroup.size(), false);
}

static bool tryMatchRecordTypes(ASTContext &Context,
                                Sema::MethodMatchStrategy strategy,
                                const Type *left, const Type *right);

static bool matchTypes(ASTContext &Context, Sema::MethodMatchStrategy strategy,
                       QualType leftQT, QualType rightQT) {
  const Type *left =
    Context.getCanonicalType(leftQT).getUnqualifiedType().getTypePtr();
  const Type *right =
    Context.getCanonicalType(rightQT).getUnqualifiedType().getTypePtr();

  if (left == right) return true;

  // If we're doing a strict match, the types have to match exactly.
  if (strategy == Sema::MMS_strict) return false;

  if (left->isIncompleteType() || right->isIncompleteType()) return false;

  // Otherwise, use this absurdly complicated algorithm to try to
  // validate the basic, low-level compatibility of the two types.

  // As a minimum, require the sizes and alignments to match.
  if (Context.getTypeInfo(left) != Context.getTypeInfo(right))
    return false;

  // Consider all the kinds of non-dependent canonical types:
  // - functions and arrays aren't possible as return and parameter types
  
  // - vector types of equal size can be arbitrarily mixed
  if (isa<VectorType>(left)) return isa<VectorType>(right);
  if (isa<VectorType>(right)) return false;

  // - references should only match references of identical type
  // - structs, unions, and Objective-C objects must match more-or-less
  //   exactly
  // - everything else should be a scalar
  if (!left->isScalarType() || !right->isScalarType())
    return tryMatchRecordTypes(Context, strategy, left, right);

  // Make scalars agree in kind, except count bools as chars, and group
  // all non-member pointers together.
  Type::ScalarTypeKind leftSK = left->getScalarTypeKind();
  Type::ScalarTypeKind rightSK = right->getScalarTypeKind();
  if (leftSK == Type::STK_Bool) leftSK = Type::STK_Integral;
  if (rightSK == Type::STK_Bool) rightSK = Type::STK_Integral;
  if (leftSK == Type::STK_CPointer || leftSK == Type::STK_BlockPointer)
    leftSK = Type::STK_ObjCObjectPointer;
  if (rightSK == Type::STK_CPointer || rightSK == Type::STK_BlockPointer)
    rightSK = Type::STK_ObjCObjectPointer;

  // Note that data member pointers and function member pointers don't
  // intermix because of the size differences.

  return (leftSK == rightSK);
}

static bool tryMatchRecordTypes(ASTContext &Context,
                                Sema::MethodMatchStrategy strategy,
                                const Type *lt, const Type *rt) {
  assert(lt && rt && lt != rt);

  if (!isa<RecordType>(lt) || !isa<RecordType>(rt)) return false;
  RecordDecl *left = cast<RecordType>(lt)->getDecl();
  RecordDecl *right = cast<RecordType>(rt)->getDecl();

  // Require union-hood to match.
  if (left->isUnion() != right->isUnion()) return false;

  // Require an exact match if either is non-POD.
  if ((isa<CXXRecordDecl>(left) && !cast<CXXRecordDecl>(left)->isPOD()) ||
      (isa<CXXRecordDecl>(right) && !cast<CXXRecordDecl>(right)->isPOD()))
    return false;

  // Require size and alignment to match.
  if (Context.getTypeInfo(lt) != Context.getTypeInfo(rt)) return false;

  // Require fields to match.
  RecordDecl::field_iterator li = left->field_begin(), le = left->field_end();
  RecordDecl::field_iterator ri = right->field_begin(), re = right->field_end();
  for (; li != le && ri != re; ++li, ++ri) {
    if (!matchTypes(Context, strategy, li->getType(), ri->getType()))
      return false;
  }
  return (li == le && ri == re);
}

/// MatchTwoMethodDeclarations - Checks that two methods have matching type and
/// returns true, or false, accordingly.
/// TODO: Handle protocol list; such as id<p1,p2> in type comparisons
bool Sema::MatchTwoMethodDeclarations(const ObjCMethodDecl *left,
                                      const ObjCMethodDecl *right,
                                      MethodMatchStrategy strategy) {
  if (!matchTypes(Context, strategy,
                  left->getResultType(), right->getResultType()))
    return false;

  // If either is hidden, it is not considered to match.
  if (left->isHidden() || right->isHidden())
    return false;

  if (getLangOpts().ObjCAutoRefCount &&
      (left->hasAttr<NSReturnsRetainedAttr>()
         != right->hasAttr<NSReturnsRetainedAttr>() ||
       left->hasAttr<NSConsumesSelfAttr>()
         != right->hasAttr<NSConsumesSelfAttr>()))
    return false;

  ObjCMethodDecl::param_const_iterator
    li = left->param_begin(), le = left->param_end(), ri = right->param_begin(),
    re = right->param_end();

  for (; li != le && ri != re; ++li, ++ri) {
    assert(ri != right->param_end() && "Param mismatch");
    const ParmVarDecl *lparm = *li, *rparm = *ri;

    if (!matchTypes(Context, strategy, lparm->getType(), rparm->getType()))
      return false;

    if (getLangOpts().ObjCAutoRefCount &&
        lparm->hasAttr<NSConsumedAttr>() != rparm->hasAttr<NSConsumedAttr>())
      return false;
  }
  return true;
}

void Sema::addMethodToGlobalList(ObjCMethodList *List, ObjCMethodDecl *Method) {
  // Record at the head of the list whether there were 0, 1, or >= 2 methods
  // inside categories.
  if (ObjCCategoryDecl *
        CD = dyn_cast<ObjCCategoryDecl>(Method->getDeclContext()))
    if (!CD->IsClassExtension() && List->getBits() < 2)
        List->setBits(List->getBits()+1);

  // If the list is empty, make it a singleton list.
  if (List->Method == 0) {
    List->Method = Method;
    List->setNext(0);
    return;
  }
  
  // We've seen a method with this name, see if we have already seen this type
  // signature.
  ObjCMethodList *Previous = List;
  for (; List; Previous = List, List = List->getNext()) {
    // If we are building a module, keep all of the methods.
    if (getLangOpts().Modules && !getLangOpts().CurrentModule.empty())
      continue;

    if (!MatchTwoMethodDeclarations(Method, List->Method))
      continue;
    
    ObjCMethodDecl *PrevObjCMethod = List->Method;

    // Propagate the 'defined' bit.
    if (Method->isDefined())
      PrevObjCMethod->setDefined(true);
    
    // If a method is deprecated, push it in the global pool.
    // This is used for better diagnostics.
    if (Method->isDeprecated()) {
      if (!PrevObjCMethod->isDeprecated())
        List->Method = Method;
    }
    // If new method is unavailable, push it into global pool
    // unless previous one is deprecated.
    if (Method->isUnavailable()) {
      if (PrevObjCMethod->getAvailability() < AR_Deprecated)
        List->Method = Method;
    }
    
    return;
  }
  
  // We have a new signature for an existing method - add it.
  // This is extremely rare. Only 1% of Cocoa selectors are "overloaded".
  ObjCMethodList *Mem = BumpAlloc.Allocate<ObjCMethodList>();
  Previous->setNext(new (Mem) ObjCMethodList(Method, 0));
}

/// \brief Read the contents of the method pool for a given selector from
/// external storage.
void Sema::ReadMethodPool(Selector Sel) {
  assert(ExternalSource && "We need an external AST source");
  ExternalSource->ReadMethodPool(Sel);
}

void Sema::AddMethodToGlobalPool(ObjCMethodDecl *Method, bool impl,
                                 bool instance) {
  // Ignore methods of invalid containers.
  if (cast<Decl>(Method->getDeclContext())->isInvalidDecl())
    return;

  if (ExternalSource)
    ReadMethodPool(Method->getSelector());
  
  GlobalMethodPool::iterator Pos = MethodPool.find(Method->getSelector());
  if (Pos == MethodPool.end())
    Pos = MethodPool.insert(std::make_pair(Method->getSelector(),
                                           GlobalMethods())).first;
  
  Method->setDefined(impl);
  
  ObjCMethodList &Entry = instance ? Pos->second.first : Pos->second.second;
  addMethodToGlobalList(&Entry, Method);
}

/// Determines if this is an "acceptable" loose mismatch in the global
/// method pool.  This exists mostly as a hack to get around certain
/// global mismatches which we can't afford to make warnings / errors.
/// Really, what we want is a way to take a method out of the global
/// method pool.
static bool isAcceptableMethodMismatch(ObjCMethodDecl *chosen,
                                       ObjCMethodDecl *other) {
  if (!chosen->isInstanceMethod())
    return false;

  Selector sel = chosen->getSelector();
  if (!sel.isUnarySelector() || sel.getNameForSlot(0) != "length")
    return false;

  // Don't complain about mismatches for -length if the method we
  // chose has an integral result type.
  return (chosen->getResultType()->isIntegerType());
}

ObjCMethodDecl *Sema::LookupMethodInGlobalPool(Selector Sel, SourceRange R,
                                               bool receiverIdOrClass,
                                               bool warn, bool instance) {
  if (ExternalSource)
    ReadMethodPool(Sel);
    
  GlobalMethodPool::iterator Pos = MethodPool.find(Sel);
  if (Pos == MethodPool.end())
    return 0;

  // Gather the non-hidden methods.
  ObjCMethodList &MethList = instance ? Pos->second.first : Pos->second.second;
  llvm::SmallVector<ObjCMethodDecl *, 4> Methods;
  for (ObjCMethodList *M = &MethList; M; M = M->getNext()) {
    if (M->Method && !M->Method->isHidden()) {
      // If we're not supposed to warn about mismatches, we're done.
      if (!warn)
        return M->Method;

      Methods.push_back(M->Method);
    }
  }

  // If there aren't any visible methods, we're done.
  // FIXME: Recover if there are any known-but-hidden methods?
  if (Methods.empty())
    return 0;

  if (Methods.size() == 1)
    return Methods[0];

  // We found multiple methods, so we may have to complain.
  bool issueDiagnostic = false, issueError = false;

  // We support a warning which complains about *any* difference in
  // method signature.
  bool strictSelectorMatch =
    (receiverIdOrClass && warn &&
     (Diags.getDiagnosticLevel(diag::warn_strict_multiple_method_decl,
                               R.getBegin())
        != DiagnosticsEngine::Ignored));
  if (strictSelectorMatch) {
    for (unsigned I = 1, N = Methods.size(); I != N; ++I) {
      if (!MatchTwoMethodDeclarations(Methods[0], Methods[I], MMS_strict)) {
        issueDiagnostic = true;
        break;
      }
    }
  }

  // If we didn't see any strict differences, we won't see any loose
  // differences.  In ARC, however, we also need to check for loose
  // mismatches, because most of them are errors.
  if (!strictSelectorMatch ||
      (issueDiagnostic && getLangOpts().ObjCAutoRefCount))
    for (unsigned I = 1, N = Methods.size(); I != N; ++I) {
      // This checks if the methods differ in type mismatch.
      if (!MatchTwoMethodDeclarations(Methods[0], Methods[I], MMS_loose) &&
          !isAcceptableMethodMismatch(Methods[0], Methods[I])) {
        issueDiagnostic = true;
        if (getLangOpts().ObjCAutoRefCount)
          issueError = true;
        break;
      }
    }

  if (issueDiagnostic) {
    if (issueError)
      Diag(R.getBegin(), diag::err_arc_multiple_method_decl) << Sel << R;
    else if (strictSelectorMatch)
      Diag(R.getBegin(), diag::warn_strict_multiple_method_decl) << Sel << R;
    else
      Diag(R.getBegin(), diag::warn_multiple_method_decl) << Sel << R;

    Diag(Methods[0]->getLocStart(),
         issueError ? diag::note_possibility : diag::note_using)
      << Methods[0]->getSourceRange();
    for (unsigned I = 1, N = Methods.size(); I != N; ++I) {
      Diag(Methods[I]->getLocStart(), diag::note_also_found)
        << Methods[I]->getSourceRange();
  }
  }
  return Methods[0];
}

ObjCMethodDecl *Sema::LookupImplementedMethodInGlobalPool(Selector Sel) {
  GlobalMethodPool::iterator Pos = MethodPool.find(Sel);
  if (Pos == MethodPool.end())
    return 0;

  GlobalMethods &Methods = Pos->second;

  if (Methods.first.Method && Methods.first.Method->isDefined())
    return Methods.first.Method;
  if (Methods.second.Method && Methods.second.Method->isDefined())
    return Methods.second.Method;
  return 0;
}

static void
HelperSelectorsForTypoCorrection(
                      SmallVectorImpl<const ObjCMethodDecl *> &BestMethod,
                      StringRef Typo, const ObjCMethodDecl * Method) {
  const unsigned MaxEditDistance = 1;
  unsigned BestEditDistance = MaxEditDistance + 1;
  std::string MethodName = Method->getSelector().getAsString();
  
  unsigned MinPossibleEditDistance = abs((int)MethodName.size() - (int)Typo.size());
  if (MinPossibleEditDistance > 0 &&
      Typo.size() / MinPossibleEditDistance < 1)
    return;
  unsigned EditDistance = Typo.edit_distance(MethodName, true, MaxEditDistance);
  if (EditDistance > MaxEditDistance)
    return;
  if (EditDistance == BestEditDistance)
    BestMethod.push_back(Method);
  else if (EditDistance < BestEditDistance) {
    BestMethod.clear();
    BestMethod.push_back(Method);
    BestEditDistance = EditDistance;
  }
}

static bool HelperIsMethodInObjCType(Sema &S, Selector Sel,
                                     QualType ObjectType) {
  if (ObjectType.isNull())
    return true;
  if (S.LookupMethodInObjectType(Sel, ObjectType, true/*Instance method*/))
    return true;
  return S.LookupMethodInObjectType(Sel, ObjectType, false/*Class method*/) != 0;
}

const ObjCMethodDecl *
Sema::SelectorsForTypoCorrection(Selector Sel,
                                 QualType ObjectType) {
  unsigned NumArgs = Sel.getNumArgs();
  SmallVector<const ObjCMethodDecl *, 8> Methods;
  bool ObjectIsId = true, ObjectIsClass = true;
  if (ObjectType.isNull())
    ObjectIsId = ObjectIsClass = false;
  else if (!ObjectType->isObjCObjectPointerType())
    return 0;
  else if (const ObjCObjectPointerType *ObjCPtr =
           ObjectType->getAsObjCInterfacePointerType()) {
    ObjectType = QualType(ObjCPtr->getInterfaceType(), 0);
    ObjectIsId = ObjectIsClass = false;
  }
  else if (ObjectType->isObjCIdType() || ObjectType->isObjCQualifiedIdType())
    ObjectIsClass = false;
  else if (ObjectType->isObjCClassType() || ObjectType->isObjCQualifiedClassType())
    ObjectIsId = false;
  else
    return 0;
  
  for (GlobalMethodPool::iterator b = MethodPool.begin(),
       e = MethodPool.end(); b != e; b++) {
    // instance methods
    for (ObjCMethodList *M = &b->second.first; M; M=M->getNext())
      if (M->Method &&
          (M->Method->getSelector().getNumArgs() == NumArgs) &&
          (M->Method->getSelector() != Sel)) {
        if (ObjectIsId)
          Methods.push_back(M->Method);
        else if (!ObjectIsClass &&
                 HelperIsMethodInObjCType(*this, M->Method->getSelector(), ObjectType))
          Methods.push_back(M->Method);
      }
    // class methods
    for (ObjCMethodList *M = &b->second.second; M; M=M->getNext())
      if (M->Method &&
          (M->Method->getSelector().getNumArgs() == NumArgs) &&
          (M->Method->getSelector() != Sel)) {
        if (ObjectIsClass)
          Methods.push_back(M->Method);
        else if (!ObjectIsId &&
                 HelperIsMethodInObjCType(*this, M->Method->getSelector(), ObjectType))
          Methods.push_back(M->Method);
      }
  }
  
  SmallVector<const ObjCMethodDecl *, 8> SelectedMethods;
  for (unsigned i = 0, e = Methods.size(); i < e; i++) {
    HelperSelectorsForTypoCorrection(SelectedMethods,
                                     Sel.getAsString(), Methods[i]);
  }
  return (SelectedMethods.size() == 1) ? SelectedMethods[0] : NULL;
}

static void
HelperToDiagnoseMismatchedMethodsInGlobalPool(Sema &S,
                                              ObjCMethodList &MethList) {
  ObjCMethodList *M = &MethList;
  ObjCMethodDecl *TargetMethod = M->Method;
  while (TargetMethod &&
         isa<ObjCImplDecl>(TargetMethod->getDeclContext())) {
    M = M->getNext();
    TargetMethod = M ? M->Method : 0;
  }
  if (!TargetMethod)
    return;
  bool FirstTime = true;
  for (M = M->getNext(); M; M=M->getNext()) {
    ObjCMethodDecl *MatchingMethodDecl = M->Method;
    if (isa<ObjCImplDecl>(MatchingMethodDecl->getDeclContext()))
      continue;
    if (!S.MatchTwoMethodDeclarations(TargetMethod,
                                      MatchingMethodDecl, Sema::MMS_loose)) {
      if (FirstTime) {
        FirstTime = false;
        S.Diag(TargetMethod->getLocation(), diag::warning_multiple_selectors)
        << TargetMethod->getSelector();
      }
      S.Diag(MatchingMethodDecl->getLocation(), diag::note_also_found);
    }
  }
}

void Sema::DiagnoseMismatchedMethodsInGlobalPool() {
  unsigned DIAG = diag::warning_multiple_selectors;
  if (Diags.getDiagnosticLevel(DIAG, SourceLocation())
      == DiagnosticsEngine::Ignored)
    return;
  for (GlobalMethodPool::iterator b = MethodPool.begin(),
       e = MethodPool.end(); b != e; b++) {
    // first, instance methods
    ObjCMethodList &InstMethList = b->second.first;
    HelperToDiagnoseMismatchedMethodsInGlobalPool(*this, InstMethList);
    // second, class methods
    ObjCMethodList &ClsMethList = b->second.second;
    HelperToDiagnoseMismatchedMethodsInGlobalPool(*this, ClsMethList);
  }
}

/// DiagnoseDuplicateIvars -
/// Check for duplicate ivars in the entire class at the start of 
/// \@implementation. This becomes necesssary because class extension can
/// add ivars to a class in random order which will not be known until
/// class's \@implementation is seen.
void Sema::DiagnoseDuplicateIvars(ObjCInterfaceDecl *ID, 
                                  ObjCInterfaceDecl *SID) {
  for (ObjCInterfaceDecl::ivar_iterator IVI = ID->ivar_begin(),
       IVE = ID->ivar_end(); IVI != IVE; ++IVI) {
    ObjCIvarDecl* Ivar = *IVI;
    if (Ivar->isInvalidDecl())
      continue;
    if (IdentifierInfo *II = Ivar->getIdentifier()) {
      ObjCIvarDecl* prevIvar = SID->lookupInstanceVariable(II);
      if (prevIvar) {
        Diag(Ivar->getLocation(), diag::err_duplicate_member) << II;
        Diag(prevIvar->getLocation(), diag::note_previous_declaration);
        Ivar->setInvalidDecl();
      }
    }
  }
}

Sema::ObjCContainerKind Sema::getObjCContainerKind() const {
  switch (CurContext->getDeclKind()) {
    case Decl::ObjCInterface:
      return Sema::OCK_Interface;
    case Decl::ObjCProtocol:
      return Sema::OCK_Protocol;
    case Decl::ObjCCategory:
      if (dyn_cast<ObjCCategoryDecl>(CurContext)->IsClassExtension())
        return Sema::OCK_ClassExtension;
      else
        return Sema::OCK_Category;
    case Decl::ObjCImplementation:
      return Sema::OCK_Implementation;
    case Decl::ObjCCategoryImpl:
      return Sema::OCK_CategoryImplementation;

    default:
      return Sema::OCK_None;
  }
}

// Note: For class/category implemenations, allMethods/allProperties is
// always null.
Decl *Sema::ActOnAtEnd(Scope *S, SourceRange AtEnd,
                       Decl **allMethods, unsigned allNum,
                       Decl **allProperties, unsigned pNum,
                       DeclGroupPtrTy *allTUVars, unsigned tuvNum) {

  if (getObjCContainerKind() == Sema::OCK_None)
    return 0;

  assert(AtEnd.isValid() && "Invalid location for '@end'");

  ObjCContainerDecl *OCD = dyn_cast<ObjCContainerDecl>(CurContext);
  Decl *ClassDecl = cast<Decl>(OCD);
  
  bool isInterfaceDeclKind =
        isa<ObjCInterfaceDecl>(ClassDecl) || isa<ObjCCategoryDecl>(ClassDecl)
         || isa<ObjCProtocolDecl>(ClassDecl);
  bool checkIdenticalMethods = isa<ObjCImplementationDecl>(ClassDecl);

  // FIXME: Remove these and use the ObjCContainerDecl/DeclContext.
  llvm::DenseMap<Selector, const ObjCMethodDecl*> InsMap;
  llvm::DenseMap<Selector, const ObjCMethodDecl*> ClsMap;

  for (unsigned i = 0; i < allNum; i++ ) {
    ObjCMethodDecl *Method =
      cast_or_null<ObjCMethodDecl>(allMethods[i]);

    if (!Method) continue;  // Already issued a diagnostic.
    if (Method->isInstanceMethod()) {
      /// Check for instance method of the same name with incompatible types
      const ObjCMethodDecl *&PrevMethod = InsMap[Method->getSelector()];
      bool match = PrevMethod ? MatchTwoMethodDeclarations(Method, PrevMethod)
                              : false;
      if ((isInterfaceDeclKind && PrevMethod && !match)
          || (checkIdenticalMethods && match)) {
          Diag(Method->getLocation(), diag::err_duplicate_method_decl)
            << Method->getDeclName();
          Diag(PrevMethod->getLocation(), diag::note_previous_declaration);
        Method->setInvalidDecl();
      } else {
        if (PrevMethod) {
          Method->setAsRedeclaration(PrevMethod);
          if (!Context.getSourceManager().isInSystemHeader(
                 Method->getLocation()))
            Diag(Method->getLocation(), diag::warn_duplicate_method_decl)
              << Method->getDeclName();
          Diag(PrevMethod->getLocation(), diag::note_previous_declaration);
        }
        InsMap[Method->getSelector()] = Method;
        /// The following allows us to typecheck messages to "id".
        AddInstanceMethodToGlobalPool(Method);
      }
    } else {
      /// Check for class method of the same name with incompatible types
      const ObjCMethodDecl *&PrevMethod = ClsMap[Method->getSelector()];
      bool match = PrevMethod ? MatchTwoMethodDeclarations(Method, PrevMethod)
                              : false;
      if ((isInterfaceDeclKind && PrevMethod && !match)
          || (checkIdenticalMethods && match)) {
        Diag(Method->getLocation(), diag::err_duplicate_method_decl)
          << Method->getDeclName();
        Diag(PrevMethod->getLocation(), diag::note_previous_declaration);
        Method->setInvalidDecl();
      } else {
        if (PrevMethod) {
          Method->setAsRedeclaration(PrevMethod);
          if (!Context.getSourceManager().isInSystemHeader(
                 Method->getLocation()))
            Diag(Method->getLocation(), diag::warn_duplicate_method_decl)
              << Method->getDeclName();
          Diag(PrevMethod->getLocation(), diag::note_previous_declaration);
        }
        ClsMap[Method->getSelector()] = Method;
        AddFactoryMethodToGlobalPool(Method);
      }
    }
  }
  if (isa<ObjCInterfaceDecl>(ClassDecl)) {
    // Nothing to do here.
  } else if (ObjCCategoryDecl *C = dyn_cast<ObjCCategoryDecl>(ClassDecl)) {
    // Categories are used to extend the class by declaring new methods.
    // By the same token, they are also used to add new properties. No
    // need to compare the added property to those in the class.

    if (C->IsClassExtension()) {
      ObjCInterfaceDecl *CCPrimary = C->getClassInterface();
      DiagnoseClassExtensionDupMethods(C, CCPrimary);
    }
  }
  if (ObjCContainerDecl *CDecl = dyn_cast<ObjCContainerDecl>(ClassDecl)) {
    if (CDecl->getIdentifier())
      // ProcessPropertyDecl is responsible for diagnosing conflicts with any
      // user-defined setter/getter. It also synthesizes setter/getter methods
      // and adds them to the DeclContext and global method pools.
      for (ObjCContainerDecl::prop_iterator I = CDecl->prop_begin(),
                                            E = CDecl->prop_end();
           I != E; ++I)
        ProcessPropertyDecl(*I, CDecl);
    CDecl->setAtEndRange(AtEnd);
  }
  if (ObjCImplementationDecl *IC=dyn_cast<ObjCImplementationDecl>(ClassDecl)) {
    IC->setAtEndRange(AtEnd);
    if (ObjCInterfaceDecl* IDecl = IC->getClassInterface()) {
      // Any property declared in a class extension might have user
      // declared setter or getter in current class extension or one
      // of the other class extensions. Mark them as synthesized as
      // property will be synthesized when property with same name is
      // seen in the @implementation.
      for (ObjCInterfaceDecl::visible_extensions_iterator
             Ext = IDecl->visible_extensions_begin(),
             ExtEnd = IDecl->visible_extensions_end();
           Ext != ExtEnd; ++Ext) {
        for (ObjCContainerDecl::prop_iterator I = Ext->prop_begin(),
             E = Ext->prop_end(); I != E; ++I) {
          ObjCPropertyDecl *Property = *I;
          // Skip over properties declared @dynamic
          if (const ObjCPropertyImplDecl *PIDecl
              = IC->FindPropertyImplDecl(Property->getIdentifier()))
            if (PIDecl->getPropertyImplementation() 
                  == ObjCPropertyImplDecl::Dynamic)
              continue;

          for (ObjCInterfaceDecl::visible_extensions_iterator
                 Ext = IDecl->visible_extensions_begin(),
                 ExtEnd = IDecl->visible_extensions_end();
               Ext != ExtEnd; ++Ext) {
            if (ObjCMethodDecl *GetterMethod
                  = Ext->getInstanceMethod(Property->getGetterName()))
              GetterMethod->setPropertyAccessor(true);
            if (!Property->isReadOnly())
              if (ObjCMethodDecl *SetterMethod
                    = Ext->getInstanceMethod(Property->getSetterName()))
                SetterMethod->setPropertyAccessor(true);
          }
        }
      }
      ImplMethodsVsClassMethods(S, IC, IDecl);
      AtomicPropertySetterGetterRules(IC, IDecl);
      DiagnoseOwningPropertyGetterSynthesis(IC);
  
      bool HasRootClassAttr = IDecl->hasAttr<ObjCRootClassAttr>();
      if (IDecl->getSuperClass() == NULL) {
        // This class has no superclass, so check that it has been marked with
        // __attribute((objc_root_class)).
        if (!HasRootClassAttr) {
          SourceLocation DeclLoc(IDecl->getLocation());
          SourceLocation SuperClassLoc(PP.getLocForEndOfToken(DeclLoc));
          Diag(DeclLoc, diag::warn_objc_root_class_missing)
            << IDecl->getIdentifier();
          // See if NSObject is in the current scope, and if it is, suggest
          // adding " : NSObject " to the class declaration.
          NamedDecl *IF = LookupSingleName(TUScope,
                                           NSAPIObj->getNSClassId(NSAPI::ClassId_NSObject),
                                           DeclLoc, LookupOrdinaryName);
          ObjCInterfaceDecl *NSObjectDecl = dyn_cast_or_null<ObjCInterfaceDecl>(IF);
          if (NSObjectDecl && NSObjectDecl->getDefinition()) {
            Diag(SuperClassLoc, diag::note_objc_needs_superclass)
              << FixItHint::CreateInsertion(SuperClassLoc, " : NSObject ");
          } else {
            Diag(SuperClassLoc, diag::note_objc_needs_superclass);
          }
        }
      } else if (HasRootClassAttr) {
        // Complain that only root classes may have this attribute.
        Diag(IDecl->getLocation(), diag::err_objc_root_class_subclass);
      }

      if (LangOpts.ObjCRuntime.isNonFragile()) {
        while (IDecl->getSuperClass()) {
          DiagnoseDuplicateIvars(IDecl, IDecl->getSuperClass());
          IDecl = IDecl->getSuperClass();
        }
      }
    }
    SetIvarInitializers(IC);
  } else if (ObjCCategoryImplDecl* CatImplClass =
                                   dyn_cast<ObjCCategoryImplDecl>(ClassDecl)) {
    CatImplClass->setAtEndRange(AtEnd);

    // Find category interface decl and then check that all methods declared
    // in this interface are implemented in the category @implementation.
    if (ObjCInterfaceDecl* IDecl = CatImplClass->getClassInterface()) {
      if (ObjCCategoryDecl *Cat
            = IDecl->FindCategoryDeclaration(CatImplClass->getIdentifier())) {
        ImplMethodsVsClassMethods(S, CatImplClass, Cat);
      }
    }
  }
  if (isInterfaceDeclKind) {
    // Reject invalid vardecls.
    for (unsigned i = 0; i != tuvNum; i++) {
      DeclGroupRef DG = allTUVars[i].getAsVal<DeclGroupRef>();
      for (DeclGroupRef::iterator I = DG.begin(), E = DG.end(); I != E; ++I)
        if (VarDecl *VDecl = dyn_cast<VarDecl>(*I)) {
          if (!VDecl->hasExternalStorage())
            Diag(VDecl->getLocation(), diag::err_objc_var_decl_inclass);
        }
    }
  }
  ActOnObjCContainerFinishDefinition();

  for (unsigned i = 0; i != tuvNum; i++) {
    DeclGroupRef DG = allTUVars[i].getAsVal<DeclGroupRef>();
    for (DeclGroupRef::iterator I = DG.begin(), E = DG.end(); I != E; ++I)
      (*I)->setTopLevelDeclInObjCContainer();
    Consumer.HandleTopLevelDeclInObjCContainer(DG);
  }

  ActOnDocumentableDecl(ClassDecl);
  return ClassDecl;
}


/// CvtQTToAstBitMask - utility routine to produce an AST bitmask for
/// objective-c's type qualifier from the parser version of the same info.
static Decl::ObjCDeclQualifier
CvtQTToAstBitMask(ObjCDeclSpec::ObjCDeclQualifier PQTVal) {
  return (Decl::ObjCDeclQualifier) (unsigned) PQTVal;
}

static inline
unsigned countAlignAttr(const AttrVec &A) {
  unsigned count=0;
  for (AttrVec::const_iterator i = A.begin(), e = A.end(); i != e; ++i)
    if ((*i)->getKind() == attr::Aligned)
      ++count;
  return count;
}

static inline
bool containsInvalidMethodImplAttribute(ObjCMethodDecl *IMD,
                                        const AttrVec &A) {
  // If method is only declared in implementation (private method),
  // No need to issue any diagnostics on method definition with attributes.
  if (!IMD)
    return false;
  
  // method declared in interface has no attribute. 
  // But implementation has attributes. This is invalid.
  // Except when implementation has 'Align' attribute which is
  // immaterial to method declared in interface.
  if (!IMD->hasAttrs())
    return (A.size() > countAlignAttr(A));

  const AttrVec &D = IMD->getAttrs();

  unsigned countAlignOnImpl = countAlignAttr(A);
  if (!countAlignOnImpl && (A.size() != D.size()))
    return true;
  else if (countAlignOnImpl) {
    unsigned countAlignOnDecl = countAlignAttr(D);
    if (countAlignOnDecl && (A.size() != D.size()))
      return true;
    else if (!countAlignOnDecl && 
             ((A.size()-countAlignOnImpl) != D.size()))
      return true;
  }
  
  // attributes on method declaration and definition must match exactly.
  // Note that we have at most a couple of attributes on methods, so this
  // n*n search is good enough.
  for (AttrVec::const_iterator i = A.begin(), e = A.end(); i != e; ++i) {
    if ((*i)->getKind() == attr::Aligned)
      continue;
    bool match = false;
    for (AttrVec::const_iterator i1 = D.begin(), e1 = D.end(); i1 != e1; ++i1) {
      if ((*i)->getKind() == (*i1)->getKind()) {
        match = true;
        break;
      }
    }
    if (!match)
      return true;
  }
  
  return false;
}

/// \brief Check whether the declared result type of the given Objective-C
/// method declaration is compatible with the method's class.
///
static Sema::ResultTypeCompatibilityKind 
CheckRelatedResultTypeCompatibility(Sema &S, ObjCMethodDecl *Method,
                                    ObjCInterfaceDecl *CurrentClass) {
  QualType ResultType = Method->getResultType();
  
  // If an Objective-C method inherits its related result type, then its 
  // declared result type must be compatible with its own class type. The
  // declared result type is compatible if:
  if (const ObjCObjectPointerType *ResultObjectType
                                = ResultType->getAs<ObjCObjectPointerType>()) {
    //   - it is id or qualified id, or
    if (ResultObjectType->isObjCIdType() ||
        ResultObjectType->isObjCQualifiedIdType())
      return Sema::RTC_Compatible;
  
    if (CurrentClass) {
      if (ObjCInterfaceDecl *ResultClass 
                                      = ResultObjectType->getInterfaceDecl()) {
        //   - it is the same as the method's class type, or
        if (declaresSameEntity(CurrentClass, ResultClass))
          return Sema::RTC_Compatible;
        
        //   - it is a superclass of the method's class type
        if (ResultClass->isSuperClassOf(CurrentClass))
          return Sema::RTC_Compatible;
      }      
    } else {
      // Any Objective-C pointer type might be acceptable for a protocol
      // method; we just don't know.
      return Sema::RTC_Unknown;
    }
  }
  
  return Sema::RTC_Incompatible;
}

namespace {
/// A helper class for searching for methods which a particular method
/// overrides.
class OverrideSearch {
public:
  Sema &S;
  ObjCMethodDecl *Method;
  llvm::SmallPtrSet<ObjCMethodDecl*, 4> Overridden;
  bool Recursive;

public:
  OverrideSearch(Sema &S, ObjCMethodDecl *method) : S(S), Method(method) {
    Selector selector = method->getSelector();

    // Bypass this search if we've never seen an instance/class method
    // with this selector before.
    Sema::GlobalMethodPool::iterator it = S.MethodPool.find(selector);
    if (it == S.MethodPool.end()) {
      if (!S.getExternalSource()) return;
      S.ReadMethodPool(selector);
      
      it = S.MethodPool.find(selector);
      if (it == S.MethodPool.end())
        return;
    }
    ObjCMethodList &list =
      method->isInstanceMethod() ? it->second.first : it->second.second;
    if (!list.Method) return;

    ObjCContainerDecl *container
      = cast<ObjCContainerDecl>(method->getDeclContext());

    // Prevent the search from reaching this container again.  This is
    // important with categories, which override methods from the
    // interface and each other.
    if (ObjCCategoryDecl *Category = dyn_cast<ObjCCategoryDecl>(container)) {
      searchFromContainer(container);
      if (ObjCInterfaceDecl *Interface = Category->getClassInterface())
        searchFromContainer(Interface);
    } else {
      searchFromContainer(container);
    }
  }

  typedef llvm::SmallPtrSet<ObjCMethodDecl*, 128>::iterator iterator;
  iterator begin() const { return Overridden.begin(); }
  iterator end() const { return Overridden.end(); }

private:
  void searchFromContainer(ObjCContainerDecl *container) {
    if (container->isInvalidDecl()) return;

    switch (container->getDeclKind()) {
#define OBJCCONTAINER(type, base) \
    case Decl::type: \
      searchFrom(cast<type##Decl>(container)); \
      break;
#define ABSTRACT_DECL(expansion)
#define DECL(type, base) \
    case Decl::type:
#include "clang/AST/DeclNodes.inc"
      llvm_unreachable("not an ObjC container!");
    }
  }

  void searchFrom(ObjCProtocolDecl *protocol) {
    if (!protocol->hasDefinition())
      return;
    
    // A method in a protocol declaration overrides declarations from
    // referenced ("parent") protocols.
    search(protocol->getReferencedProtocols());
  }

  void searchFrom(ObjCCategoryDecl *category) {
    // A method in a category declaration overrides declarations from
    // the main class and from protocols the category references.
    // The main class is handled in the constructor.
    search(category->getReferencedProtocols());
  }

  void searchFrom(ObjCCategoryImplDecl *impl) {
    // A method in a category definition that has a category
    // declaration overrides declarations from the category
    // declaration.
    if (ObjCCategoryDecl *category = impl->getCategoryDecl()) {
      search(category);
      if (ObjCInterfaceDecl *Interface = category->getClassInterface())
        search(Interface);

    // Otherwise it overrides declarations from the class.
    } else if (ObjCInterfaceDecl *Interface = impl->getClassInterface()) {
      search(Interface);
    }
  }

  void searchFrom(ObjCInterfaceDecl *iface) {
    // A method in a class declaration overrides declarations from
    if (!iface->hasDefinition())
      return;
    
    //   - categories,
    for (ObjCInterfaceDecl::known_categories_iterator
           cat = iface->known_categories_begin(),
           catEnd = iface->known_categories_end();
         cat != catEnd; ++cat) {
      search(*cat);
    }

    //   - the super class, and
    if (ObjCInterfaceDecl *super = iface->getSuperClass())
      search(super);

    //   - any referenced protocols.
    search(iface->getReferencedProtocols());
  }

  void searchFrom(ObjCImplementationDecl *impl) {
    // A method in a class implementation overrides declarations from
    // the class interface.
    if (ObjCInterfaceDecl *Interface = impl->getClassInterface())
      search(Interface);
  }


  void search(const ObjCProtocolList &protocols) {
    for (ObjCProtocolList::iterator i = protocols.begin(), e = protocols.end();
         i != e; ++i)
      search(*i);
  }

  void search(ObjCContainerDecl *container) {
    // Check for a method in this container which matches this selector.
    ObjCMethodDecl *meth = container->getMethod(Method->getSelector(),
                                                Method->isInstanceMethod(),
                                                /*AllowHidden=*/true);

    // If we find one, record it and bail out.
    if (meth) {
      Overridden.insert(meth);
      return;
    }

    // Otherwise, search for methods that a hypothetical method here
    // would have overridden.

    // Note that we're now in a recursive case.
    Recursive = true;

    searchFromContainer(container);
  }
};
}

void Sema::CheckObjCMethodOverrides(ObjCMethodDecl *ObjCMethod,
                                    ObjCInterfaceDecl *CurrentClass,
                                    ResultTypeCompatibilityKind RTC) {
  // Search for overridden methods and merge information down from them.
  OverrideSearch overrides(*this, ObjCMethod);
  // Keep track if the method overrides any method in the class's base classes,
  // its protocols, or its categories' protocols; we will keep that info
  // in the ObjCMethodDecl.
  // For this info, a method in an implementation is not considered as
  // overriding the same method in the interface or its categories.
  bool hasOverriddenMethodsInBaseOrProtocol = false;
  for (OverrideSearch::iterator
         i = overrides.begin(), e = overrides.end(); i != e; ++i) {
    ObjCMethodDecl *overridden = *i;

    if (!hasOverriddenMethodsInBaseOrProtocol) {
      if (isa<ObjCProtocolDecl>(overridden->getDeclContext()) ||
          CurrentClass != overridden->getClassInterface() ||
          overridden->isOverriding()) {
        hasOverriddenMethodsInBaseOrProtocol = true;

      } else if (isa<ObjCImplDecl>(ObjCMethod->getDeclContext())) {
        // OverrideSearch will return as "overridden" the same method in the
        // interface. For hasOverriddenMethodsInBaseOrProtocol, we need to
        // check whether a category of a base class introduced a method with the
        // same selector, after the interface method declaration.
        // To avoid unnecessary lookups in the majority of cases, we use the
        // extra info bits in GlobalMethodPool to check whether there were any
        // category methods with this selector.
        GlobalMethodPool::iterator It =
            MethodPool.find(ObjCMethod->getSelector());
        if (It != MethodPool.end()) {
          ObjCMethodList &List =
            ObjCMethod->isInstanceMethod()? It->second.first: It->second.second;
          unsigned CategCount = List.getBits();
          if (CategCount > 0) {
            // If the method is in a category we'll do lookup if there were at
            // least 2 category methods recorded, otherwise only one will do.
            if (CategCount > 1 ||
                !isa<ObjCCategoryImplDecl>(overridden->getDeclContext())) {
              OverrideSearch overrides(*this, overridden);
              for (OverrideSearch::iterator
                     OI= overrides.begin(), OE= overrides.end(); OI!=OE; ++OI) {
                ObjCMethodDecl *SuperOverridden = *OI;
                if (isa<ObjCProtocolDecl>(SuperOverridden->getDeclContext()) ||
                    CurrentClass != SuperOverridden->getClassInterface()) {
                  hasOverriddenMethodsInBaseOrProtocol = true;
                  overridden->setOverriding(true);
                  break;
                }
              }
            }
          }
        }
      }
    }

    // Propagate down the 'related result type' bit from overridden methods.
    if (RTC != Sema::RTC_Incompatible && overridden->hasRelatedResultType())
      ObjCMethod->SetRelatedResultType();

    // Then merge the declarations.
    mergeObjCMethodDecls(ObjCMethod, overridden);

    if (ObjCMethod->isImplicit() && overridden->isImplicit())
      continue; // Conflicting properties are detected elsewhere.

    // Check for overriding methods
    if (isa<ObjCInterfaceDecl>(ObjCMethod->getDeclContext()) || 
        isa<ObjCImplementationDecl>(ObjCMethod->getDeclContext()))
      CheckConflictingOverridingMethod(ObjCMethod, overridden,
              isa<ObjCProtocolDecl>(overridden->getDeclContext()));
    
    if (CurrentClass && overridden->getDeclContext() != CurrentClass &&
        isa<ObjCInterfaceDecl>(overridden->getDeclContext()) &&
        !overridden->isImplicit() /* not meant for properties */) {
      ObjCMethodDecl::param_iterator ParamI = ObjCMethod->param_begin(),
                                          E = ObjCMethod->param_end();
      ObjCMethodDecl::param_iterator PrevI = overridden->param_begin(),
                                     PrevE = overridden->param_end();
      for (; ParamI != E && PrevI != PrevE; ++ParamI, ++PrevI) {
        assert(PrevI != overridden->param_end() && "Param mismatch");
        QualType T1 = Context.getCanonicalType((*ParamI)->getType());
        QualType T2 = Context.getCanonicalType((*PrevI)->getType());
        // If type of argument of method in this class does not match its
        // respective argument type in the super class method, issue warning;
        if (!Context.typesAreCompatible(T1, T2)) {
          Diag((*ParamI)->getLocation(), diag::ext_typecheck_base_super)
            << T1 << T2;
          Diag(overridden->getLocation(), diag::note_previous_declaration);
          break;
        }
      }
    }
  }

  ObjCMethod->setOverriding(hasOverriddenMethodsInBaseOrProtocol);
}

Decl *Sema::ActOnMethodDeclaration(
    Scope *S,
    SourceLocation MethodLoc, SourceLocation EndLoc,
    tok::TokenKind MethodType, 
    ObjCDeclSpec &ReturnQT, ParsedType ReturnType,
    ArrayRef<SourceLocation> SelectorLocs,
    Selector Sel,
    // optional arguments. The number of types/arguments is obtained
    // from the Sel.getNumArgs().
    ObjCArgInfo *ArgInfo,
    DeclaratorChunk::ParamInfo *CParamInfo, unsigned CNumArgs, // c-style args
    AttributeList *AttrList, tok::ObjCKeywordKind MethodDeclKind,
    bool isVariadic, bool MethodDefinition) {
  // Make sure we can establish a context for the method.
  if (!CurContext->isObjCContainer()) {
    Diag(MethodLoc, diag::error_missing_method_context);
    return 0;
  }
  ObjCContainerDecl *OCD = dyn_cast<ObjCContainerDecl>(CurContext);
  Decl *ClassDecl = cast<Decl>(OCD); 
  QualType resultDeclType;

  bool HasRelatedResultType = false;
  TypeSourceInfo *ResultTInfo = 0;
  if (ReturnType) {
    resultDeclType = GetTypeFromParser(ReturnType, &ResultTInfo);

    if (CheckFunctionReturnType(resultDeclType, MethodLoc))
      return 0;

    HasRelatedResultType = (resultDeclType == Context.getObjCInstanceType());
  } else { // get the type for "id".
    resultDeclType = Context.getObjCIdType();
    Diag(MethodLoc, diag::warn_missing_method_return_type)
      << FixItHint::CreateInsertion(SelectorLocs.front(), "(id)");
  }

  ObjCMethodDecl* ObjCMethod =
    ObjCMethodDecl::Create(Context, MethodLoc, EndLoc, Sel,
                           resultDeclType,
                           ResultTInfo,
                           CurContext,
                           MethodType == tok::minus, isVariadic,
                           /*isPropertyAccessor=*/false,
                           /*isImplicitlyDeclared=*/false, /*isDefined=*/false,
                           MethodDeclKind == tok::objc_optional 
                             ? ObjCMethodDecl::Optional
                             : ObjCMethodDecl::Required,
                           HasRelatedResultType);

  SmallVector<ParmVarDecl*, 16> Params;

  for (unsigned i = 0, e = Sel.getNumArgs(); i != e; ++i) {
    QualType ArgType;
    TypeSourceInfo *DI;

    if (!ArgInfo[i].Type) {
      ArgType = Context.getObjCIdType();
      DI = 0;
    } else {
      ArgType = GetTypeFromParser(ArgInfo[i].Type, &DI);
    }

    LookupResult R(*this, ArgInfo[i].Name, ArgInfo[i].NameLoc, 
                   LookupOrdinaryName, ForRedeclaration);
    LookupName(R, S);
    if (R.isSingleResult()) {
      NamedDecl *PrevDecl = R.getFoundDecl();
      if (S->isDeclScope(PrevDecl)) {
        Diag(ArgInfo[i].NameLoc, 
             (MethodDefinition ? diag::warn_method_param_redefinition 
                               : diag::warn_method_param_declaration)) 
          << ArgInfo[i].Name;
        Diag(PrevDecl->getLocation(), 
             diag::note_previous_declaration);
      }
    }

    SourceLocation StartLoc = DI
      ? DI->getTypeLoc().getBeginLoc()
      : ArgInfo[i].NameLoc;

    ParmVarDecl* Param = CheckParameter(ObjCMethod, StartLoc,
                                        ArgInfo[i].NameLoc, ArgInfo[i].Name,
                                        ArgType, DI, SC_None);

    Param->setObjCMethodScopeInfo(i);

    Param->setObjCDeclQualifier(
      CvtQTToAstBitMask(ArgInfo[i].DeclSpec.getObjCDeclQualifier()));

    // Apply the attributes to the parameter.
    ProcessDeclAttributeList(TUScope, Param, ArgInfo[i].ArgAttrs);

    if (Param->hasAttr<BlocksAttr>()) {
      Diag(Param->getLocation(), diag::err_block_on_nonlocal);
      Param->setInvalidDecl();
    }
    S->AddDecl(Param);
    IdResolver.AddDecl(Param);

    Params.push_back(Param);
  }
  
  for (unsigned i = 0, e = CNumArgs; i != e; ++i) {
    ParmVarDecl *Param = cast<ParmVarDecl>(CParamInfo[i].Param);
    QualType ArgType = Param->getType();
    if (ArgType.isNull())
      ArgType = Context.getObjCIdType();
    else
      // Perform the default array/function conversions (C99 6.7.5.3p[7,8]).
      ArgType = Context.getAdjustedParameterType(ArgType);

    Param->setDeclContext(ObjCMethod);
    Params.push_back(Param);
  }
  
  ObjCMethod->setMethodParams(Context, Params, SelectorLocs);
  ObjCMethod->setObjCDeclQualifier(
    CvtQTToAstBitMask(ReturnQT.getObjCDeclQualifier()));

  if (AttrList)
    ProcessDeclAttributeList(TUScope, ObjCMethod, AttrList);

  // Add the method now.
  const ObjCMethodDecl *PrevMethod = 0;
  if (ObjCImplDecl *ImpDecl = dyn_cast<ObjCImplDecl>(ClassDecl)) {
    if (MethodType == tok::minus) {
      PrevMethod = ImpDecl->getInstanceMethod(Sel);
      ImpDecl->addInstanceMethod(ObjCMethod);
    } else {
      PrevMethod = ImpDecl->getClassMethod(Sel);
      ImpDecl->addClassMethod(ObjCMethod);
    }

    ObjCMethodDecl *IMD = 0;
    if (ObjCInterfaceDecl *IDecl = ImpDecl->getClassInterface())
      IMD = IDecl->lookupMethod(ObjCMethod->getSelector(), 
                                ObjCMethod->isInstanceMethod());
    if (ObjCMethod->hasAttrs() &&
        containsInvalidMethodImplAttribute(IMD, ObjCMethod->getAttrs())) {
      SourceLocation MethodLoc = IMD->getLocation();
      if (!getSourceManager().isInSystemHeader(MethodLoc)) {
        Diag(EndLoc, diag::warn_attribute_method_def);
        Diag(MethodLoc, diag::note_method_declared_at)
          << ObjCMethod->getDeclName();
      }
    }
  } else {
    cast<DeclContext>(ClassDecl)->addDecl(ObjCMethod);
  }

  if (PrevMethod) {
    // You can never have two method definitions with the same name.
    Diag(ObjCMethod->getLocation(), diag::err_duplicate_method_decl)
      << ObjCMethod->getDeclName();
    Diag(PrevMethod->getLocation(), diag::note_previous_declaration);
    ObjCMethod->setInvalidDecl();
    return ObjCMethod;
  }

  // If this Objective-C method does not have a related result type, but we
  // are allowed to infer related result types, try to do so based on the
  // method family.
  ObjCInterfaceDecl *CurrentClass = dyn_cast<ObjCInterfaceDecl>(ClassDecl);
  if (!CurrentClass) {
    if (ObjCCategoryDecl *Cat = dyn_cast<ObjCCategoryDecl>(ClassDecl))
      CurrentClass = Cat->getClassInterface();
    else if (ObjCImplDecl *Impl = dyn_cast<ObjCImplDecl>(ClassDecl))
      CurrentClass = Impl->getClassInterface();
    else if (ObjCCategoryImplDecl *CatImpl
                                   = dyn_cast<ObjCCategoryImplDecl>(ClassDecl))
      CurrentClass = CatImpl->getClassInterface();
  }

  ResultTypeCompatibilityKind RTC
    = CheckRelatedResultTypeCompatibility(*this, ObjCMethod, CurrentClass);

  CheckObjCMethodOverrides(ObjCMethod, CurrentClass, RTC);

  bool ARCError = false;
  if (getLangOpts().ObjCAutoRefCount)
    ARCError = CheckARCMethodDecl(ObjCMethod);

  // Infer the related result type when possible.
  if (!ARCError && RTC == Sema::RTC_Compatible &&
      !ObjCMethod->hasRelatedResultType() &&
      LangOpts.ObjCInferRelatedResultType) {
    bool InferRelatedResultType = false;
    switch (ObjCMethod->getMethodFamily()) {
    case OMF_None:
    case OMF_copy:
    case OMF_dealloc:
    case OMF_finalize:
    case OMF_mutableCopy:
    case OMF_release:
    case OMF_retainCount:
    case OMF_performSelector:
      break;
      
    case OMF_alloc:
    case OMF_new:
      InferRelatedResultType = ObjCMethod->isClassMethod();
      break;
        
    case OMF_init:
    case OMF_autorelease:
    case OMF_retain:
    case OMF_self:
      InferRelatedResultType = ObjCMethod->isInstanceMethod();
      break;
    }
    
    if (InferRelatedResultType)
      ObjCMethod->SetRelatedResultType();
  }

  ActOnDocumentableDecl(ObjCMethod);

  return ObjCMethod;
}

bool Sema::CheckObjCDeclScope(Decl *D) {
  // Following is also an error. But it is caused by a missing @end
  // and diagnostic is issued elsewhere.
  if (isa<ObjCContainerDecl>(CurContext->getRedeclContext()))
    return false;

  // If we switched context to translation unit while we are still lexically in
  // an objc container, it means the parser missed emitting an error.
  if (isa<TranslationUnitDecl>(getCurLexicalContext()->getRedeclContext()))
    return false;
  
  Diag(D->getLocation(), diag::err_objc_decls_may_only_appear_in_global_scope);
  D->setInvalidDecl();

  return true;
}

/// Called whenever \@defs(ClassName) is encountered in the source.  Inserts the
/// instance variables of ClassName into Decls.
void Sema::ActOnDefs(Scope *S, Decl *TagD, SourceLocation DeclStart,
                     IdentifierInfo *ClassName,
                     SmallVectorImpl<Decl*> &Decls) {
  // Check that ClassName is a valid class
  ObjCInterfaceDecl *Class = getObjCInterfaceDecl(ClassName, DeclStart);
  if (!Class) {
    Diag(DeclStart, diag::err_undef_interface) << ClassName;
    return;
  }
  if (LangOpts.ObjCRuntime.isNonFragile()) {
    Diag(DeclStart, diag::err_atdef_nonfragile_interface);
    return;
  }

  // Collect the instance variables
  SmallVector<const ObjCIvarDecl*, 32> Ivars;
  Context.DeepCollectObjCIvars(Class, true, Ivars);
  // For each ivar, create a fresh ObjCAtDefsFieldDecl.
  for (unsigned i = 0; i < Ivars.size(); i++) {
    const FieldDecl* ID = cast<FieldDecl>(Ivars[i]);
    RecordDecl *Record = dyn_cast<RecordDecl>(TagD);
    Decl *FD = ObjCAtDefsFieldDecl::Create(Context, Record,
                                           /*FIXME: StartL=*/ID->getLocation(),
                                           ID->getLocation(),
                                           ID->getIdentifier(), ID->getType(),
                                           ID->getBitWidth());
    Decls.push_back(FD);
  }

  // Introduce all of these fields into the appropriate scope.
  for (SmallVectorImpl<Decl*>::iterator D = Decls.begin();
       D != Decls.end(); ++D) {
    FieldDecl *FD = cast<FieldDecl>(*D);
    if (getLangOpts().CPlusPlus)
      PushOnScopeChains(cast<FieldDecl>(FD), S);
    else if (RecordDecl *Record = dyn_cast<RecordDecl>(TagD))
      Record->addDecl(FD);
  }
}

/// \brief Build a type-check a new Objective-C exception variable declaration.
VarDecl *Sema::BuildObjCExceptionDecl(TypeSourceInfo *TInfo, QualType T,
                                      SourceLocation StartLoc,
                                      SourceLocation IdLoc,
                                      IdentifierInfo *Id,
                                      bool Invalid) {
  // ISO/IEC TR 18037 S6.7.3: "The type of an object with automatic storage 
  // duration shall not be qualified by an address-space qualifier."
  // Since all parameters have automatic store duration, they can not have
  // an address space.
  if (T.getAddressSpace() != 0) {
    Diag(IdLoc, diag::err_arg_with_address_space);
    Invalid = true;
  }
  
  // An @catch parameter must be an unqualified object pointer type;
  // FIXME: Recover from "NSObject foo" by inserting the * in "NSObject *foo"?
  if (Invalid) {
    // Don't do any further checking.
  } else if (T->isDependentType()) {
    // Okay: we don't know what this type will instantiate to.
  } else if (!T->isObjCObjectPointerType()) {
    Invalid = true;
    Diag(IdLoc ,diag::err_catch_param_not_objc_type);
  } else if (T->isObjCQualifiedIdType()) {
    Invalid = true;
    Diag(IdLoc, diag::err_illegal_qualifiers_on_catch_parm);
  }
  
  VarDecl *New = VarDecl::Create(Context, CurContext, StartLoc, IdLoc, Id,
                                 T, TInfo, SC_None);
  New->setExceptionVariable(true);
  
  // In ARC, infer 'retaining' for variables of retainable type.
  if (getLangOpts().ObjCAutoRefCount && inferObjCARCLifetime(New))
    Invalid = true;

  if (Invalid)
    New->setInvalidDecl();
  return New;
}

Decl *Sema::ActOnObjCExceptionDecl(Scope *S, Declarator &D) {
  const DeclSpec &DS = D.getDeclSpec();
  
  // We allow the "register" storage class on exception variables because
  // GCC did, but we drop it completely. Any other storage class is an error.
  if (DS.getStorageClassSpec() == DeclSpec::SCS_register) {
    Diag(DS.getStorageClassSpecLoc(), diag::warn_register_objc_catch_parm)
      << FixItHint::CreateRemoval(SourceRange(DS.getStorageClassSpecLoc()));
  } else if (DeclSpec::SCS SCS = DS.getStorageClassSpec()) {
    Diag(DS.getStorageClassSpecLoc(), diag::err_storage_spec_on_catch_parm)
      << DeclSpec::getSpecifierName(SCS);
  }
  if (DeclSpec::TSCS TSCS = D.getDeclSpec().getThreadStorageClassSpec())
    Diag(D.getDeclSpec().getThreadStorageClassSpecLoc(),
         diag::err_invalid_thread)
     << DeclSpec::getSpecifierName(TSCS);
  D.getMutableDeclSpec().ClearStorageClassSpecs();

  DiagnoseFunctionSpecifiers(D.getDeclSpec());
  
  // Check that there are no default arguments inside the type of this
  // exception object (C++ only).
  if (getLangOpts().CPlusPlus)
    CheckExtraCXXDefaultArguments(D);
  
  TypeSourceInfo *TInfo = GetTypeForDeclarator(D, S);
  QualType ExceptionType = TInfo->getType();

  VarDecl *New = BuildObjCExceptionDecl(TInfo, ExceptionType,
                                        D.getSourceRange().getBegin(),
                                        D.getIdentifierLoc(),
                                        D.getIdentifier(),
                                        D.isInvalidType());
  
  // Parameter declarators cannot be qualified (C++ [dcl.meaning]p1).
  if (D.getCXXScopeSpec().isSet()) {
    Diag(D.getIdentifierLoc(), diag::err_qualified_objc_catch_parm)
      << D.getCXXScopeSpec().getRange();
    New->setInvalidDecl();
  }
  
  // Add the parameter declaration into this scope.
  S->AddDecl(New);
  if (D.getIdentifier())
    IdResolver.AddDecl(New);
  
  ProcessDeclAttributes(S, New, D);
  
  if (New->hasAttr<BlocksAttr>())
    Diag(New->getLocation(), diag::err_block_on_nonlocal);
  return New;
}

/// CollectIvarsToConstructOrDestruct - Collect those ivars which require
/// initialization.
void Sema::CollectIvarsToConstructOrDestruct(ObjCInterfaceDecl *OI,
                                SmallVectorImpl<ObjCIvarDecl*> &Ivars) {
  for (ObjCIvarDecl *Iv = OI->all_declared_ivar_begin(); Iv; 
       Iv= Iv->getNextIvar()) {
    QualType QT = Context.getBaseElementType(Iv->getType());
    if (QT->isRecordType())
      Ivars.push_back(Iv);
  }
}

void Sema::DiagnoseUseOfUnimplementedSelectors() {
  // Load referenced selectors from the external source.
  if (ExternalSource) {
    SmallVector<std::pair<Selector, SourceLocation>, 4> Sels;
    ExternalSource->ReadReferencedSelectors(Sels);
    for (unsigned I = 0, N = Sels.size(); I != N; ++I)
      ReferencedSelectors[Sels[I].first] = Sels[I].second;
  }
  
  DiagnoseMismatchedMethodsInGlobalPool();
  
  // Warning will be issued only when selector table is
  // generated (which means there is at lease one implementation
  // in the TU). This is to match gcc's behavior.
  if (ReferencedSelectors.empty() || 
      !Context.AnyObjCImplementation())
    return;
  for (llvm::DenseMap<Selector, SourceLocation>::iterator S = 
        ReferencedSelectors.begin(),
       E = ReferencedSelectors.end(); S != E; ++S) {
    Selector Sel = (*S).first;
    if (!LookupImplementedMethodInGlobalPool(Sel))
      Diag((*S).second, diag::warn_unimplemented_selector) << Sel;
  }
  return;
}

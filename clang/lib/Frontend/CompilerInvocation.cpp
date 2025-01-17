//===--- CompilerInvocation.cpp -------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "clang/Frontend/CompilerInvocation.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/FileManager.h"
#include "clang/Basic/Version.h"
#include "clang/Driver/DriverDiagnostic.h"
#include "clang/Driver/Options.h"
#include "clang/Driver/Util.h"
#include "clang/Frontend/LangStandard.h"
#include "clang/Frontend/Utils.h"
#include "clang/Lex/HeaderSearchOptions.h"
#include "clang/Serialization/ASTReader.h"
#include "llvm/ADT/Hashing.h"
#include "llvm/ADT/OwningPtr.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringSwitch.h"
#include "llvm/ADT/Triple.h"
#include "llvm/Option/Arg.h"
#include "llvm/Option/ArgList.h"
#include "llvm/Option/OptTable.h"
#include "llvm/Option/Option.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/Host.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/PathV1.h"
#include "llvm/Support/system_error.h"
#include <sys/stat.h>
using namespace clang;

//===----------------------------------------------------------------------===//
// Initialization.
//===----------------------------------------------------------------------===//

CompilerInvocationBase::CompilerInvocationBase()
  : LangOpts(new LangOptions()), TargetOpts(new TargetOptions()),
    DiagnosticOpts(new DiagnosticOptions()),
    HeaderSearchOpts(new HeaderSearchOptions()),
    PreprocessorOpts(new PreprocessorOptions()) {}

CompilerInvocationBase::CompilerInvocationBase(const CompilerInvocationBase &X)
  : RefCountedBase<CompilerInvocation>(),
    LangOpts(new LangOptions(*X.getLangOpts())), 
    TargetOpts(new TargetOptions(X.getTargetOpts())),
    DiagnosticOpts(new DiagnosticOptions(X.getDiagnosticOpts())),
    HeaderSearchOpts(new HeaderSearchOptions(X.getHeaderSearchOpts())),
    PreprocessorOpts(new PreprocessorOptions(X.getPreprocessorOpts())) {}

//===----------------------------------------------------------------------===//
// Deserialization (from args)
//===----------------------------------------------------------------------===//

using namespace clang::driver;
using namespace clang::driver::options;
using namespace llvm::opt;

//

static unsigned getOptimizationLevel(ArgList &Args, InputKind IK,
                                     DiagnosticsEngine &Diags) {
  unsigned DefaultOpt = 0;
  if (IK == IK_OpenCL && !Args.hasArg(OPT_cl_opt_disable))
    DefaultOpt = 2;

  if (Arg *A = Args.getLastArg(options::OPT_O_Group)) {
    if (A->getOption().matches(options::OPT_O0))
      return 0;

    if (A->getOption().matches(options::OPT_Ofast))
      return 3;

    assert (A->getOption().matches(options::OPT_O));

    StringRef S(A->getValue());
    if (S == "s" || S == "z" || S.empty())
      return 2;

    return getLastArgIntValue(Args, OPT_O, DefaultOpt, Diags);
  }

  return DefaultOpt;
}

static unsigned getOptimizationLevelSize(ArgList &Args) {
  if (Arg *A = Args.getLastArg(options::OPT_O_Group)) {
    if (A->getOption().matches(options::OPT_O)) {
      switch (A->getValue()[0]) {
      default:
        return 0;
      case 's':
        return 1;
      case 'z':
        return 2;
      }
    }
  }
  return 0;
}

static void addWarningArgs(ArgList &Args, std::vector<std::string> &Warnings) {
  for (arg_iterator I = Args.filtered_begin(OPT_W_Group),
         E = Args.filtered_end(); I != E; ++I) {
    Arg *A = *I;
    // If the argument is a pure flag, add its name (minus the "W" at the beginning)
    // to the warning list. Else, add its value (for the OPT_W case).
    if (A->getOption().getKind() == Option::FlagClass) {
      Warnings.push_back(A->getOption().getName().substr(1));
    } else {
      for (unsigned Idx = 0, End = A->getNumValues();
           Idx < End; ++Idx) {
        StringRef V = A->getValue(Idx);
        // "-Wl," and such are not warning options.
        // FIXME: Should be handled by putting these in separate flags.
        if (V.startswith("l,") || V.startswith("a,") || V.startswith("p,"))
          continue;

        Warnings.push_back(V);
      }
    }
  }
}

static bool ParseAnalyzerArgs(AnalyzerOptions &Opts, ArgList &Args,
                              DiagnosticsEngine &Diags) {
  using namespace options;
  bool Success = true;
  if (Arg *A = Args.getLastArg(OPT_analyzer_store)) {
    StringRef Name = A->getValue();
    AnalysisStores Value = llvm::StringSwitch<AnalysisStores>(Name)
#define ANALYSIS_STORE(NAME, CMDFLAG, DESC, CREATFN) \
      .Case(CMDFLAG, NAME##Model)
#include "clang/StaticAnalyzer/Core/Analyses.def"
      .Default(NumStores);
    if (Value == NumStores) {
      Diags.Report(diag::err_drv_invalid_value)
        << A->getAsString(Args) << Name;
      Success = false;
    } else {
      Opts.AnalysisStoreOpt = Value;
    }
  }

  if (Arg *A = Args.getLastArg(OPT_analyzer_constraints)) {
    StringRef Name = A->getValue();
    AnalysisConstraints Value = llvm::StringSwitch<AnalysisConstraints>(Name)
#define ANALYSIS_CONSTRAINTS(NAME, CMDFLAG, DESC, CREATFN) \
      .Case(CMDFLAG, NAME##Model)
#include "clang/StaticAnalyzer/Core/Analyses.def"
      .Default(NumConstraints);
    if (Value == NumConstraints) {
      Diags.Report(diag::err_drv_invalid_value)
        << A->getAsString(Args) << Name;
      Success = false;
    } else {
      Opts.AnalysisConstraintsOpt = Value;
    }
  }

  if (Arg *A = Args.getLastArg(OPT_analyzer_output)) {
    StringRef Name = A->getValue();
    AnalysisDiagClients Value = llvm::StringSwitch<AnalysisDiagClients>(Name)
#define ANALYSIS_DIAGNOSTICS(NAME, CMDFLAG, DESC, CREATFN, AUTOCREAT) \
      .Case(CMDFLAG, PD_##NAME)
#include "clang/StaticAnalyzer/Core/Analyses.def"
      .Default(NUM_ANALYSIS_DIAG_CLIENTS);
    if (Value == NUM_ANALYSIS_DIAG_CLIENTS) {
      Diags.Report(diag::err_drv_invalid_value)
        << A->getAsString(Args) << Name;
      Success = false;
    } else {
      Opts.AnalysisDiagOpt = Value;
    }
  }

  if (Arg *A = Args.getLastArg(OPT_analyzer_purge)) {
    StringRef Name = A->getValue();
    AnalysisPurgeMode Value = llvm::StringSwitch<AnalysisPurgeMode>(Name)
#define ANALYSIS_PURGE(NAME, CMDFLAG, DESC) \
      .Case(CMDFLAG, NAME)
#include "clang/StaticAnalyzer/Core/Analyses.def"
      .Default(NumPurgeModes);
    if (Value == NumPurgeModes) {
      Diags.Report(diag::err_drv_invalid_value)
        << A->getAsString(Args) << Name;
      Success = false;
    } else {
      Opts.AnalysisPurgeOpt = Value;
    }
  }

  if (Arg *A = Args.getLastArg(OPT_analyzer_inlining_mode)) {
    StringRef Name = A->getValue();
    AnalysisInliningMode Value = llvm::StringSwitch<AnalysisInliningMode>(Name)
#define ANALYSIS_INLINING_MODE(NAME, CMDFLAG, DESC) \
      .Case(CMDFLAG, NAME)
#include "clang/StaticAnalyzer/Core/Analyses.def"
      .Default(NumInliningModes);
    if (Value == NumInliningModes) {
      Diags.Report(diag::err_drv_invalid_value)
        << A->getAsString(Args) << Name;
      Success = false;
    } else {
      Opts.InliningMode = Value;
    }
  }

  Opts.ShowCheckerHelp = Args.hasArg(OPT_analyzer_checker_help);
  Opts.visualizeExplodedGraphWithGraphViz =
    Args.hasArg(OPT_analyzer_viz_egraph_graphviz);
  Opts.visualizeExplodedGraphWithUbiGraph =
    Args.hasArg(OPT_analyzer_viz_egraph_ubigraph);
  Opts.NoRetryExhausted = Args.hasArg(OPT_analyzer_disable_retry_exhausted);
  Opts.AnalyzeAll = Args.hasArg(OPT_analyzer_opt_analyze_headers);
  Opts.AnalyzerDisplayProgress = Args.hasArg(OPT_analyzer_display_progress);
  Opts.AnalyzeNestedBlocks =
    Args.hasArg(OPT_analyzer_opt_analyze_nested_blocks);
  Opts.eagerlyAssumeBinOpBifurcation = Args.hasArg(OPT_analyzer_eagerly_assume);
  Opts.AnalyzeSpecificFunction = Args.getLastArgValue(OPT_analyze_function);
  Opts.UnoptimizedCFG = Args.hasArg(OPT_analysis_UnoptimizedCFG);
  Opts.TrimGraph = Args.hasArg(OPT_trim_egraph);
  Opts.maxBlockVisitOnPath =
      getLastArgIntValue(Args, OPT_analyzer_max_loop, 4, Diags);
  Opts.PrintStats = Args.hasArg(OPT_analyzer_stats);
  Opts.InlineMaxStackDepth =
      getLastArgIntValue(Args, OPT_analyzer_inline_max_stack_depth,
                         Opts.InlineMaxStackDepth, Diags);

  Opts.CheckersControlList.clear();
  for (arg_iterator it = Args.filtered_begin(OPT_analyzer_checker,
                                             OPT_analyzer_disable_checker),
         ie = Args.filtered_end(); it != ie; ++it) {
    const Arg *A = *it;
    A->claim();
    bool enable = (A->getOption().getID() == OPT_analyzer_checker);
    // We can have a list of comma separated checker names, e.g:
    // '-analyzer-checker=cocoa,unix'
    StringRef checkerList = A->getValue();
    SmallVector<StringRef, 4> checkers;
    checkerList.split(checkers, ",");
    for (unsigned i = 0, e = checkers.size(); i != e; ++i)
      Opts.CheckersControlList.push_back(std::make_pair(checkers[i], enable));
  }
  
  // Go through the analyzer configuration options.
  for (arg_iterator it = Args.filtered_begin(OPT_analyzer_config),
       ie = Args.filtered_end(); it != ie; ++it) {
    const Arg *A = *it;
    A->claim();
    // We can have a list of comma separated config names, e.g:
    // '-analyzer-config key1=val1,key2=val2'
    StringRef configList = A->getValue();
    SmallVector<StringRef, 4> configVals;
    configList.split(configVals, ",");
    for (unsigned i = 0, e = configVals.size(); i != e; ++i) {
      StringRef key, val;
      llvm::tie(key, val) = configVals[i].split("=");
      if (val.empty()) {
        Diags.Report(SourceLocation(),
                     diag::err_analyzer_config_no_value) << configVals[i];
        Success = false;
        break;
      }
      if (val.find('=') != StringRef::npos) {
        Diags.Report(SourceLocation(),
                     diag::err_analyzer_config_multiple_values)
          << configVals[i];
        Success = false;
        break;
      }
      Opts.Config[key] = val;
    }
  }

  return Success;
}

static bool ParseMigratorArgs(MigratorOptions &Opts, ArgList &Args) {
  Opts.NoNSAllocReallocError = Args.hasArg(OPT_migrator_no_nsalloc_error);
  Opts.NoFinalizeRemoval = Args.hasArg(OPT_migrator_no_finalize_removal);
  return true;
}

static void ParseCommentArgs(CommentOptions &Opts, ArgList &Args) {
  Opts.BlockCommandNames = Args.getAllArgValues(OPT_fcomment_block_commands);
  Opts.ParseAllComments = Args.hasArg(OPT_fparse_all_comments);
}

static bool ParseCodeGenArgs(CodeGenOptions &Opts, ArgList &Args, InputKind IK,
                             DiagnosticsEngine &Diags) {
  using namespace options;
  bool Success = true;

  unsigned OptLevel = getOptimizationLevel(Args, IK, Diags);
  if (OptLevel > 3) {
    Diags.Report(diag::err_drv_invalid_value)
      << Args.getLastArg(OPT_O)->getAsString(Args) << OptLevel;
    OptLevel = 3;
    Success = false;
  }
  Opts.OptimizationLevel = OptLevel;

  // We must always run at least the always inlining pass.
  Opts.setInlining(
    (Opts.OptimizationLevel > 1) ? CodeGenOptions::NormalInlining
                                 : CodeGenOptions::OnlyAlwaysInlining);
  // -fno-inline-functions overrides OptimizationLevel > 1.
  Opts.NoInline = Args.hasArg(OPT_fno_inline);
  Opts.setInlining(Args.hasArg(OPT_fno_inline_functions) ?
                     CodeGenOptions::OnlyAlwaysInlining : Opts.getInlining());

  if (Args.hasArg(OPT_gline_tables_only)) {
    Opts.setDebugInfo(CodeGenOptions::DebugLineTablesOnly);
  } else if (Args.hasArg(OPT_g_Flag) || Args.hasArg(OPT_gdwarf_2) ||
             Args.hasArg(OPT_gdwarf_3) || Args.hasArg(OPT_gdwarf_4)) {
    if (Args.hasFlag(OPT_flimit_debug_info, OPT_fno_limit_debug_info, true))
      Opts.setDebugInfo(CodeGenOptions::LimitedDebugInfo);
    else
      Opts.setDebugInfo(CodeGenOptions::FullDebugInfo);
  }
  Opts.DebugColumnInfo = Args.hasArg(OPT_dwarf_column_info);
  Opts.SplitDwarfFile = Args.getLastArgValue(OPT_split_dwarf_file);
  if (Args.hasArg(OPT_gdwarf_2))
    Opts.DwarfVersion = 2;
  else if (Args.hasArg(OPT_gdwarf_3))
    Opts.DwarfVersion = 3;
  else if (Args.hasArg(OPT_gdwarf_4))
    Opts.DwarfVersion = 4;
  else if (Opts.getDebugInfo() != CodeGenOptions::NoDebugInfo)
    // Default Dwarf version is 3 if we are generating debug information.
    Opts.DwarfVersion = 3;

  Opts.DisableLLVMOpts = Args.hasArg(OPT_disable_llvm_optzns);
  Opts.DisableRedZone = Args.hasArg(OPT_disable_red_zone);
  Opts.ForbidGuardVariables = Args.hasArg(OPT_fforbid_guard_variables);
  Opts.UseRegisterSizedBitfieldAccess = Args.hasArg(
    OPT_fuse_register_sized_bitfield_access);
  Opts.RelaxedAliasing = Args.hasArg(OPT_relaxed_aliasing);
  Opts.StructPathTBAA = Args.hasArg(OPT_struct_path_tbaa);
  Opts.DwarfDebugFlags = Args.getLastArgValue(OPT_dwarf_debug_flags);
  Opts.MergeAllConstants = !Args.hasArg(OPT_fno_merge_all_constants);
  Opts.NoCommon = Args.hasArg(OPT_fno_common);
  Opts.NoImplicitFloat = Args.hasArg(OPT_no_implicit_float);
  Opts.OptimizeSize = getOptimizationLevelSize(Args);
  Opts.SimplifyLibCalls = !(Args.hasArg(OPT_fno_builtin) ||
                            Args.hasArg(OPT_ffreestanding));
  Opts.UnrollLoops = Args.hasArg(OPT_funroll_loops) ||
                     (Opts.OptimizationLevel > 1 && !Opts.OptimizeSize);

  Opts.Autolink = !Args.hasArg(OPT_fno_autolink);
  Opts.AsmVerbose = Args.hasArg(OPT_masm_verbose);
  Opts.ObjCAutoRefCountExceptions = Args.hasArg(OPT_fobjc_arc_exceptions);
  Opts.CUDAIsDevice = Args.hasArg(OPT_fcuda_is_device);
  Opts.CXAAtExit = !Args.hasArg(OPT_fno_use_cxa_atexit);
  Opts.CXXCtorDtorAliases = Args.hasArg(OPT_mconstructor_aliases);
  Opts.CodeModel = Args.getLastArgValue(OPT_mcode_model);
  Opts.DebugPass = Args.getLastArgValue(OPT_mdebug_pass);
  Opts.DisableFPElim = Args.hasArg(OPT_mdisable_fp_elim);
  Opts.DisableFree = Args.hasArg(OPT_disable_free);
  Opts.DisableTailCalls = Args.hasArg(OPT_mdisable_tail_calls);
  Opts.FloatABI = Args.getLastArgValue(OPT_mfloat_abi);
  Opts.HiddenWeakVTables = Args.hasArg(OPT_fhidden_weak_vtables);
  Opts.LessPreciseFPMAD = Args.hasArg(OPT_cl_mad_enable);
  Opts.LimitFloatPrecision = Args.getLastArgValue(OPT_mlimit_float_precision);
  Opts.NoInfsFPMath = (Args.hasArg(OPT_menable_no_infinities) ||
                       Args.hasArg(OPT_cl_finite_math_only)||
                       Args.hasArg(OPT_cl_fast_relaxed_math));
  Opts.NoNaNsFPMath = (Args.hasArg(OPT_menable_no_nans) ||
                       Args.hasArg(OPT_cl_finite_math_only)||
                       Args.hasArg(OPT_cl_fast_relaxed_math));
  Opts.NoZeroInitializedInBSS = Args.hasArg(OPT_mno_zero_initialized_in_bss);
  Opts.BackendOptions = Args.getAllArgValues(OPT_backend_option);
  Opts.NumRegisterParameters = getLastArgIntValue(Args, OPT_mregparm, 0, Diags);
  Opts.NoGlobalMerge = Args.hasArg(OPT_mno_global_merge);
  Opts.NoExecStack = Args.hasArg(OPT_mno_exec_stack);
  Opts.EnableSegmentedStacks = Args.hasArg(OPT_split_stacks);
  Opts.RelaxAll = Args.hasArg(OPT_mrelax_all);
  Opts.OmitLeafFramePointer = Args.hasArg(OPT_momit_leaf_frame_pointer);
  Opts.SaveTempLabels = Args.hasArg(OPT_msave_temp_labels);
  Opts.NoDwarf2CFIAsm = Args.hasArg(OPT_fno_dwarf2_cfi_asm);
  Opts.NoDwarfDirectoryAsm = Args.hasArg(OPT_fno_dwarf_directory_asm);
  Opts.SoftFloat = Args.hasArg(OPT_msoft_float);
  Opts.StrictEnums = Args.hasArg(OPT_fstrict_enums);
  Opts.UnsafeFPMath = Args.hasArg(OPT_menable_unsafe_fp_math) ||
                      Args.hasArg(OPT_cl_unsafe_math_optimizations) ||
                      Args.hasArg(OPT_cl_fast_relaxed_math);
  Opts.UnwindTables = Args.hasArg(OPT_munwind_tables);
  Opts.RelocationModel = Args.getLastArgValue(OPT_mrelocation_model, "pic");
  Opts.TrapFuncName = Args.getLastArgValue(OPT_ftrap_function_EQ);
  Opts.UseInitArray = Args.hasArg(OPT_fuse_init_array);

  Opts.FunctionSections = Args.hasArg(OPT_ffunction_sections);
  Opts.DataSections = Args.hasArg(OPT_fdata_sections);

  Opts.MainFileName = Args.getLastArgValue(OPT_main_file_name);
  Opts.VerifyModule = !Args.hasArg(OPT_disable_llvm_verifier);
  Opts.SanitizeRecover = !Args.hasArg(OPT_fno_sanitize_recover);

  Opts.DisableGCov = Args.hasArg(OPT_test_coverage);
  Opts.EmitGcovArcs = Args.hasArg(OPT_femit_coverage_data);
  Opts.EmitGcovNotes = Args.hasArg(OPT_femit_coverage_notes);
  if (Opts.EmitGcovArcs || Opts.EmitGcovNotes) {
  Opts.CoverageFile = Args.getLastArgValue(OPT_coverage_file);
    Opts.CoverageExtraChecksum = Args.hasArg(OPT_coverage_cfg_checksum);
    Opts.CoverageNoFunctionNamesInData =
        Args.hasArg(OPT_coverage_no_function_names_in_data);
    if (Args.hasArg(OPT_coverage_version_EQ)) {
      StringRef CoverageVersion = Args.getLastArgValue(OPT_coverage_version_EQ);
      if (CoverageVersion.size() != 4) {
        Diags.Report(diag::err_drv_invalid_value)
            << Args.getLastArg(OPT_coverage_version_EQ)->getAsString(Args)
            << CoverageVersion;
      } else {
        memcpy(Opts.CoverageVersion, CoverageVersion.data(), 4);
      }
    }
  }

  Opts.InstrumentFunctions = Args.hasArg(OPT_finstrument_functions);
  Opts.InstrumentForProfiling = Args.hasArg(OPT_pg);
  Opts.EmitOpenCLArgMetadata = Args.hasArg(OPT_cl_kernel_arg_info);
  Opts.DebugCompilationDir = Args.getLastArgValue(OPT_fdebug_compilation_dir);
  Opts.LinkBitcodeFile = Args.getLastArgValue(OPT_mlink_bitcode_file);
  Opts.SanitizerBlacklistFile = Args.getLastArgValue(OPT_fsanitize_blacklist);
  Opts.SanitizeMemoryTrackOrigins =
    Args.hasArg(OPT_fsanitize_memory_track_origins);
  Opts.SanitizeAddressZeroBaseShadow =
    Args.hasArg(OPT_fsanitize_address_zero_base_shadow);
  Opts.SanitizeUndefinedTrapOnError =
    Args.hasArg(OPT_fsanitize_undefined_trap_on_error);
  Opts.SSPBufferSize =
      getLastArgIntValue(Args, OPT_stack_protector_buffer_size, 8, Diags);
  Opts.StackRealignment = Args.hasArg(OPT_mstackrealign);
  if (Arg *A = Args.getLastArg(OPT_mstack_alignment)) {
    StringRef Val = A->getValue();
    unsigned StackAlignment = Opts.StackAlignment;
    Val.getAsInteger(10, StackAlignment);
    Opts.StackAlignment = StackAlignment;
  }

  if (Arg *A = Args.getLastArg(OPT_fobjc_dispatch_method_EQ)) {
    StringRef Name = A->getValue();
    unsigned Method = llvm::StringSwitch<unsigned>(Name)
      .Case("legacy", CodeGenOptions::Legacy)
      .Case("non-legacy", CodeGenOptions::NonLegacy)
      .Case("mixed", CodeGenOptions::Mixed)
      .Default(~0U);
    if (Method == ~0U) {
      Diags.Report(diag::err_drv_invalid_value) << A->getAsString(Args) << Name;
      Success = false;
    } else {
      Opts.setObjCDispatchMethod(
        static_cast<CodeGenOptions::ObjCDispatchMethodKind>(Method));
    }
  }

  if (Arg *A = Args.getLastArg(OPT_ftlsmodel_EQ)) {
    StringRef Name = A->getValue();
    unsigned Model = llvm::StringSwitch<unsigned>(Name)
        .Case("global-dynamic", CodeGenOptions::GeneralDynamicTLSModel)
        .Case("local-dynamic", CodeGenOptions::LocalDynamicTLSModel)
        .Case("initial-exec", CodeGenOptions::InitialExecTLSModel)
        .Case("local-exec", CodeGenOptions::LocalExecTLSModel)
        .Default(~0U);
    if (Model == ~0U) {
      Diags.Report(diag::err_drv_invalid_value) << A->getAsString(Args) << Name;
      Success = false;
    } else {
      Opts.setDefaultTLSModel(static_cast<CodeGenOptions::TLSModel>(Model));
    }
  }

  if (Arg *A = Args.getLastArg(OPT_ffp_contract)) {
    StringRef Val = A->getValue();
    if (Val == "fast")
      Opts.setFPContractMode(CodeGenOptions::FPC_Fast);
    else if (Val == "on")
      Opts.setFPContractMode(CodeGenOptions::FPC_On);
    else if (Val == "off")
      Opts.setFPContractMode(CodeGenOptions::FPC_Off);
    else
      Diags.Report(diag::err_drv_invalid_value) << A->getAsString(Args) << Val;
  }

  if (Arg *A = Args.getLastArg(OPT_fpcc_struct_return, OPT_freg_struct_return)) {
    if (A->getOption().matches(OPT_fpcc_struct_return)) {
      Opts.setStructReturnConvention(CodeGenOptions::SRCK_OnStack);
    } else {
      assert(A->getOption().matches(OPT_freg_struct_return));
      Opts.setStructReturnConvention(CodeGenOptions::SRCK_InRegs);
    }
  }

  return Success;
}

static void ParseDependencyOutputArgs(DependencyOutputOptions &Opts,
                                      ArgList &Args) {
  using namespace options;
  Opts.OutputFile = Args.getLastArgValue(OPT_dependency_file);
  Opts.Targets = Args.getAllArgValues(OPT_MT);
  Opts.IncludeSystemHeaders = Args.hasArg(OPT_sys_header_deps);
  Opts.UsePhonyTargets = Args.hasArg(OPT_MP);
  Opts.ShowHeaderIncludes = Args.hasArg(OPT_H);
  Opts.HeaderIncludeOutputFile = Args.getLastArgValue(OPT_header_include_file);
  Opts.AddMissingHeaderDeps = Args.hasArg(OPT_MG);
  Opts.DOTOutputFile = Args.getLastArgValue(OPT_dependency_dot);
}

bool clang::ParseDiagnosticArgs(DiagnosticOptions &Opts, ArgList &Args,
                                DiagnosticsEngine *Diags) {
  using namespace options;
  bool Success = true;

  Opts.DiagnosticLogFile = Args.getLastArgValue(OPT_diagnostic_log_file);
  Opts.DiagnosticSerializationFile =
    Args.getLastArgValue(OPT_diagnostic_serialized_file);
  Opts.IgnoreWarnings = Args.hasArg(OPT_w);
  Opts.NoRewriteMacros = Args.hasArg(OPT_Wno_rewrite_macros);
  Opts.Pedantic = Args.hasArg(OPT_pedantic);
  Opts.PedanticErrors = Args.hasArg(OPT_pedantic_errors);
  Opts.ShowCarets = !Args.hasArg(OPT_fno_caret_diagnostics);
  Opts.ShowColors = Args.hasArg(OPT_fcolor_diagnostics);
  Opts.ShowColumn = Args.hasFlag(OPT_fshow_column,
                                 OPT_fno_show_column,
                                 /*Default=*/true);
  Opts.ShowFixits = !Args.hasArg(OPT_fno_diagnostics_fixit_info);
  Opts.ShowLocation = !Args.hasArg(OPT_fno_show_source_location);
  Opts.ShowOptionNames = Args.hasArg(OPT_fdiagnostics_show_option);

  // Default behavior is to not to show note include stacks.
  Opts.ShowNoteIncludeStack = false;
  if (Arg *A = Args.getLastArg(OPT_fdiagnostics_show_note_include_stack,
                               OPT_fno_diagnostics_show_note_include_stack))
    if (A->getOption().matches(OPT_fdiagnostics_show_note_include_stack))
      Opts.ShowNoteIncludeStack = true;

  StringRef ShowOverloads =
    Args.getLastArgValue(OPT_fshow_overloads_EQ, "all");
  if (ShowOverloads == "best")
    Opts.setShowOverloads(Ovl_Best);
  else if (ShowOverloads == "all")
    Opts.setShowOverloads(Ovl_All);
  else {
    Success = false;
    if (Diags)
      Diags->Report(diag::err_drv_invalid_value)
      << Args.getLastArg(OPT_fshow_overloads_EQ)->getAsString(Args)
      << ShowOverloads;
  }

  StringRef ShowCategory =
    Args.getLastArgValue(OPT_fdiagnostics_show_category, "none");
  if (ShowCategory == "none")
    Opts.ShowCategories = 0;
  else if (ShowCategory == "id")
    Opts.ShowCategories = 1;
  else if (ShowCategory == "name")
    Opts.ShowCategories = 2;
  else {
    Success = false;
    if (Diags)
      Diags->Report(diag::err_drv_invalid_value)
      << Args.getLastArg(OPT_fdiagnostics_show_category)->getAsString(Args)
      << ShowCategory;
  }

  StringRef Format =
    Args.getLastArgValue(OPT_fdiagnostics_format, "clang");
  if (Format == "clang")
    Opts.setFormat(DiagnosticOptions::Clang);
  else if (Format == "msvc")
    Opts.setFormat(DiagnosticOptions::Msvc);
  else if (Format == "vi")
    Opts.setFormat(DiagnosticOptions::Vi);
  else {
    Success = false;
    if (Diags)
      Diags->Report(diag::err_drv_invalid_value)
      << Args.getLastArg(OPT_fdiagnostics_format)->getAsString(Args)
      << Format;
  }
  
  Opts.ShowSourceRanges = Args.hasArg(OPT_fdiagnostics_print_source_range_info);
  Opts.ShowParseableFixits = Args.hasArg(OPT_fdiagnostics_parseable_fixits);
  Opts.ShowPresumedLoc = !Args.hasArg(OPT_fno_diagnostics_use_presumed_location);
  Opts.VerifyDiagnostics = Args.hasArg(OPT_verify);
  Opts.ElideType = !Args.hasArg(OPT_fno_elide_type);
  Opts.ShowTemplateTree = Args.hasArg(OPT_fdiagnostics_show_template_tree);
  Opts.ErrorLimit = getLastArgIntValue(Args, OPT_ferror_limit, 0, Diags);
  Opts.MacroBacktraceLimit =
      getLastArgIntValue(Args, OPT_fmacro_backtrace_limit,
                         DiagnosticOptions::DefaultMacroBacktraceLimit, Diags);
  Opts.TemplateBacktraceLimit = getLastArgIntValue(
      Args, OPT_ftemplate_backtrace_limit,
      DiagnosticOptions::DefaultTemplateBacktraceLimit, Diags);
  Opts.ConstexprBacktraceLimit = getLastArgIntValue(
      Args, OPT_fconstexpr_backtrace_limit,
      DiagnosticOptions::DefaultConstexprBacktraceLimit, Diags);
  Opts.TabStop = getLastArgIntValue(Args, OPT_ftabstop,
                                    DiagnosticOptions::DefaultTabStop, Diags);
  if (Opts.TabStop == 0 || Opts.TabStop > DiagnosticOptions::MaxTabStop) {
    Opts.TabStop = DiagnosticOptions::DefaultTabStop;
    if (Diags)
      Diags->Report(diag::warn_ignoring_ftabstop_value)
      << Opts.TabStop << DiagnosticOptions::DefaultTabStop;
  }
  Opts.MessageLength = getLastArgIntValue(Args, OPT_fmessage_length, 0, Diags);
  addWarningArgs(Args, Opts.Warnings);

  return Success;
}

static void ParseFileSystemArgs(FileSystemOptions &Opts, ArgList &Args) {
  Opts.WorkingDir = Args.getLastArgValue(OPT_working_directory);
}

static InputKind ParseFrontendArgs(FrontendOptions &Opts, ArgList &Args,
                                   DiagnosticsEngine &Diags) {
  using namespace options;
  Opts.ProgramAction = frontend::ParseSyntaxOnly;
  if (const Arg *A = Args.getLastArg(OPT_Action_Group)) {
    switch (A->getOption().getID()) {
    default:
      llvm_unreachable("Invalid option in group!");
    case OPT_ast_list:
      Opts.ProgramAction = frontend::ASTDeclList; break;
    case OPT_ast_dump:
      Opts.ProgramAction = frontend::ASTDump; break;
    case OPT_ast_dump_xml:
      Opts.ProgramAction = frontend::ASTDumpXML; break;
    case OPT_ast_print:
      Opts.ProgramAction = frontend::ASTPrint; break;
    case OPT_ast_view:
      Opts.ProgramAction = frontend::ASTView; break;
    case OPT_dump_raw_tokens:
      Opts.ProgramAction = frontend::DumpRawTokens; break;
    case OPT_dump_tokens:
      Opts.ProgramAction = frontend::DumpTokens; break;
    case OPT_S:
      Opts.ProgramAction = frontend::EmitAssembly; break;
    case OPT_emit_llvm_bc:
      Opts.ProgramAction = frontend::EmitBC; break;
    case OPT_emit_html:
      Opts.ProgramAction = frontend::EmitHTML; break;
    case OPT_emit_llvm:
      Opts.ProgramAction = frontend::EmitLLVM; break;
    case OPT_emit_llvm_only:
      Opts.ProgramAction = frontend::EmitLLVMOnly; break;
    case OPT_emit_codegen_only:
      Opts.ProgramAction = frontend::EmitCodeGenOnly; break;
    case OPT_emit_obj:
      Opts.ProgramAction = frontend::EmitObj; break;
    case OPT_fixit_EQ:
      Opts.FixItSuffix = A->getValue();
      // fall-through!
    case OPT_fixit:
      Opts.ProgramAction = frontend::FixIt; break;
    case OPT_emit_module:
      Opts.ProgramAction = frontend::GenerateModule; break;
    case OPT_emit_pch:
      Opts.ProgramAction = frontend::GeneratePCH; break;
    case OPT_emit_pth:
      Opts.ProgramAction = frontend::GeneratePTH; break;
    case OPT_init_only:
      Opts.ProgramAction = frontend::InitOnly; break;
    case OPT_fsyntax_only:
      Opts.ProgramAction = frontend::ParseSyntaxOnly; break;
    case OPT_module_file_info:
      Opts.ProgramAction = frontend::ModuleFileInfo; break;
    case OPT_print_decl_contexts:
      Opts.ProgramAction = frontend::PrintDeclContext; break;
    case OPT_print_preamble:
      Opts.ProgramAction = frontend::PrintPreamble; break;
    case OPT_E:
      Opts.ProgramAction = frontend::PrintPreprocessedInput; break;
    case OPT_rewrite_macros:
      Opts.ProgramAction = frontend::RewriteMacros; break;
    case OPT_rewrite_objc:
      Opts.ProgramAction = frontend::RewriteObjC; break;
    case OPT_rewrite_test:
      Opts.ProgramAction = frontend::RewriteTest; break;
    case OPT_analyze:
      Opts.ProgramAction = frontend::RunAnalysis; break;
    case OPT_migrate:
      Opts.ProgramAction = frontend::MigrateSource; break;
    case OPT_Eonly:
      Opts.ProgramAction = frontend::RunPreprocessorOnly; break;
    }
  }

  if (const Arg* A = Args.getLastArg(OPT_plugin)) {
    Opts.Plugins.push_back(A->getValue(0));
    Opts.ProgramAction = frontend::PluginAction;
    Opts.ActionName = A->getValue();

    for (arg_iterator it = Args.filtered_begin(OPT_plugin_arg),
           end = Args.filtered_end(); it != end; ++it) {
      if ((*it)->getValue(0) == Opts.ActionName)
        Opts.PluginArgs.push_back((*it)->getValue(1));
    }
  }

  Opts.AddPluginActions = Args.getAllArgValues(OPT_add_plugin);
  Opts.AddPluginArgs.resize(Opts.AddPluginActions.size());
  for (int i = 0, e = Opts.AddPluginActions.size(); i != e; ++i) {
    for (arg_iterator it = Args.filtered_begin(OPT_plugin_arg),
           end = Args.filtered_end(); it != end; ++it) {
      if ((*it)->getValue(0) == Opts.AddPluginActions[i])
        Opts.AddPluginArgs[i].push_back((*it)->getValue(1));
    }
  }

  if (const Arg *A = Args.getLastArg(OPT_code_completion_at)) {
    Opts.CodeCompletionAt =
      ParsedSourceLocation::FromString(A->getValue());
    if (Opts.CodeCompletionAt.FileName.empty())
      Diags.Report(diag::err_drv_invalid_value)
        << A->getAsString(Args) << A->getValue();
  }
  Opts.DisableFree = Args.hasArg(OPT_disable_free);

  Opts.OutputFile = Args.getLastArgValue(OPT_o);
  Opts.Plugins = Args.getAllArgValues(OPT_load);
  Opts.RelocatablePCH = Args.hasArg(OPT_relocatable_pch);
  Opts.ShowHelp = Args.hasArg(OPT_help);
  Opts.ShowStats = Args.hasArg(OPT_print_stats);
  Opts.ShowTimers = Args.hasArg(OPT_ftime_report);
  Opts.ShowVersion = Args.hasArg(OPT_version);
  Opts.ASTMergeFiles = Args.getAllArgValues(OPT_ast_merge);
  Opts.LLVMArgs = Args.getAllArgValues(OPT_mllvm);
  Opts.FixWhatYouCan = Args.hasArg(OPT_fix_what_you_can);
  Opts.FixOnlyWarnings = Args.hasArg(OPT_fix_only_warnings);
  Opts.FixAndRecompile = Args.hasArg(OPT_fixit_recompile);
  Opts.FixToTemporaries = Args.hasArg(OPT_fixit_to_temp);
  Opts.ASTDumpFilter = Args.getLastArgValue(OPT_ast_dump_filter);
  Opts.UseGlobalModuleIndex = !Args.hasArg(OPT_fno_modules_global_index);
  Opts.GenerateGlobalModuleIndex = Opts.UseGlobalModuleIndex;
  
  Opts.CodeCompleteOpts.IncludeMacros
    = Args.hasArg(OPT_code_completion_macros);
  Opts.CodeCompleteOpts.IncludeCodePatterns
    = Args.hasArg(OPT_code_completion_patterns);
  Opts.CodeCompleteOpts.IncludeGlobals
    = !Args.hasArg(OPT_no_code_completion_globals);
  Opts.CodeCompleteOpts.IncludeBriefComments
    = Args.hasArg(OPT_code_completion_brief_comments);

  Opts.OverrideRecordLayoutsFile
    = Args.getLastArgValue(OPT_foverride_record_layout_EQ);
  if (const Arg *A = Args.getLastArg(OPT_arcmt_check,
                                     OPT_arcmt_modify,
                                     OPT_arcmt_migrate)) {
    switch (A->getOption().getID()) {
    default:
      llvm_unreachable("missed a case");
    case OPT_arcmt_check:
      Opts.ARCMTAction = FrontendOptions::ARCMT_Check;
      break;
    case OPT_arcmt_modify:
      Opts.ARCMTAction = FrontendOptions::ARCMT_Modify;
      break;
    case OPT_arcmt_migrate:
      Opts.ARCMTAction = FrontendOptions::ARCMT_Migrate;
      break;
    }
  }
  Opts.MTMigrateDir = Args.getLastArgValue(OPT_mt_migrate_directory);
  Opts.ARCMTMigrateReportOut
    = Args.getLastArgValue(OPT_arcmt_migrate_report_output);
  Opts.ARCMTMigrateEmitARCErrors
    = Args.hasArg(OPT_arcmt_migrate_emit_arc_errors);

  if (Args.hasArg(OPT_objcmt_migrate_literals))
    Opts.ObjCMTAction |= FrontendOptions::ObjCMT_Literals;
  if (Args.hasArg(OPT_objcmt_migrate_subscripting))
    Opts.ObjCMTAction |= FrontendOptions::ObjCMT_Subscripting;

  if (Opts.ARCMTAction != FrontendOptions::ARCMT_None &&
      Opts.ObjCMTAction != FrontendOptions::ObjCMT_None) {
    Diags.Report(diag::err_drv_argument_not_allowed_with)
      << "ARC migration" << "ObjC migration";
  }

  InputKind DashX = IK_None;
  if (const Arg *A = Args.getLastArg(OPT_x)) {
    DashX = llvm::StringSwitch<InputKind>(A->getValue())
      .Case("c", IK_C)
      .Case("cl", IK_OpenCL)
      .Case("cuda", IK_CUDA)
      .Case("c++", IK_CXX)
      .Case("objective-c", IK_ObjC)
      .Case("objective-c++", IK_ObjCXX)
      .Case("cpp-output", IK_PreprocessedC)
      .Case("assembler-with-cpp", IK_Asm)
      .Case("c++-cpp-output", IK_PreprocessedCXX)
      .Case("objective-c-cpp-output", IK_PreprocessedObjC)
      .Case("objc-cpp-output", IK_PreprocessedObjC)
      .Case("objective-c++-cpp-output", IK_PreprocessedObjCXX)
      .Case("objc++-cpp-output", IK_PreprocessedObjCXX)
      .Case("c-header", IK_C)
      .Case("cl-header", IK_OpenCL)
      .Case("objective-c-header", IK_ObjC)
      .Case("c++-header", IK_CXX)
      .Case("objective-c++-header", IK_ObjCXX)
      .Cases("ast", "pcm", IK_AST)
      .Case("ir", IK_LLVM_IR)
      .Default(IK_None);
    if (DashX == IK_None)
      Diags.Report(diag::err_drv_invalid_value)
        << A->getAsString(Args) << A->getValue();
  }

  // '-' is the default input if none is given.
  std::vector<std::string> Inputs = Args.getAllArgValues(OPT_INPUT);
  Opts.Inputs.clear();
  if (Inputs.empty())
    Inputs.push_back("-");
  for (unsigned i = 0, e = Inputs.size(); i != e; ++i) {
    InputKind IK = DashX;
    if (IK == IK_None) {
      IK = FrontendOptions::getInputKindForExtension(
        StringRef(Inputs[i]).rsplit('.').second);
      // FIXME: Remove this hack.
      if (i == 0)
        DashX = IK;
    }
    Opts.Inputs.push_back(FrontendInputFile(Inputs[i], IK));
  }

  return DashX;
}

std::string CompilerInvocation::GetResourcesPath(const char *Argv0,
                                                 void *MainAddr) {
  llvm::sys::Path P = llvm::sys::Path::GetMainExecutable(Argv0, MainAddr);

  if (!P.isEmpty()) {
    P.eraseComponent();  // Remove /clang from foo/bin/clang
    P.eraseComponent();  // Remove /bin   from foo/bin

    // Get foo/lib/clang/<version>/include
    P.appendComponent("lib");
    P.appendComponent("clang");
    P.appendComponent(CLANG_VERSION_STRING);
  }

  return P.str();
}

static void ParseHeaderSearchArgs(HeaderSearchOptions &Opts, ArgList &Args) {
  using namespace options;
  Opts.Sysroot = Args.getLastArgValue(OPT_isysroot, "/");
  Opts.Verbose = Args.hasArg(OPT_v);
  Opts.UseBuiltinIncludes = !Args.hasArg(OPT_nobuiltininc);
  Opts.UseStandardSystemIncludes = !Args.hasArg(OPT_nostdsysteminc);
  Opts.UseStandardCXXIncludes = !Args.hasArg(OPT_nostdincxx);
  if (const Arg *A = Args.getLastArg(OPT_stdlib_EQ))
    Opts.UseLibcxx = (strcmp(A->getValue(), "libc++") == 0);
  Opts.ResourceDir = Args.getLastArgValue(OPT_resource_dir);
  Opts.ModuleCachePath = Args.getLastArgValue(OPT_fmodules_cache_path);
  Opts.DisableModuleHash = Args.hasArg(OPT_fdisable_module_hash);
  Opts.ModuleCachePruneInterval =
      getLastArgIntValue(Args, OPT_fmodules_prune_interval, 7 * 24 * 60 * 60);
  Opts.ModuleCachePruneAfter =
      getLastArgIntValue(Args, OPT_fmodules_prune_after, 31 * 24 * 60 * 60);
  for (arg_iterator it = Args.filtered_begin(OPT_fmodules_ignore_macro),
                    ie = Args.filtered_end();
       it != ie; ++it) {
    StringRef MacroDef = (*it)->getValue();
    Opts.ModulesIgnoreMacros.insert(MacroDef.split('=').first);
  }

  // Add -I..., -F..., and -index-header-map options in order.
  bool IsIndexHeaderMap = false;
  for (arg_iterator it = Args.filtered_begin(OPT_I, OPT_F, 
                                             OPT_index_header_map),
       ie = Args.filtered_end(); it != ie; ++it) {
    if ((*it)->getOption().matches(OPT_index_header_map)) {
      // -index-header-map applies to the next -I or -F.
      IsIndexHeaderMap = true;
      continue;
    }
        
    frontend::IncludeDirGroup Group 
      = IsIndexHeaderMap? frontend::IndexHeaderMap : frontend::Angled;
    
    Opts.AddPath((*it)->getValue(), Group,
                 /*IsFramework=*/ (*it)->getOption().matches(OPT_F), true);
    IsIndexHeaderMap = false;
  }

  // Add -iprefix/-iwithprefix/-iwithprefixbefore options.
  StringRef Prefix = ""; // FIXME: This isn't the correct default prefix.
  for (arg_iterator it = Args.filtered_begin(OPT_iprefix, OPT_iwithprefix,
                                             OPT_iwithprefixbefore),
         ie = Args.filtered_end(); it != ie; ++it) {
    const Arg *A = *it;
    if (A->getOption().matches(OPT_iprefix))
      Prefix = A->getValue();
    else if (A->getOption().matches(OPT_iwithprefix))
      Opts.AddPath(Prefix.str() + A->getValue(),
                   frontend::After, false, true);
    else
      Opts.AddPath(Prefix.str() + A->getValue(),
                   frontend::Angled, false, true);
  }

  for (arg_iterator it = Args.filtered_begin(OPT_idirafter),
         ie = Args.filtered_end(); it != ie; ++it)
    Opts.AddPath((*it)->getValue(), frontend::After, false, true);
  for (arg_iterator it = Args.filtered_begin(OPT_iquote),
         ie = Args.filtered_end(); it != ie; ++it)
    Opts.AddPath((*it)->getValue(), frontend::Quoted, false, true);
  for (arg_iterator it = Args.filtered_begin(OPT_isystem,
         OPT_iwithsysroot), ie = Args.filtered_end(); it != ie; ++it)
    Opts.AddPath((*it)->getValue(), frontend::System, false,
                 !(*it)->getOption().matches(OPT_iwithsysroot));
  for (arg_iterator it = Args.filtered_begin(OPT_iframework),
         ie = Args.filtered_end(); it != ie; ++it)
    Opts.AddPath((*it)->getValue(), frontend::System, true, true);

  // Add the paths for the various language specific isystem flags.
  for (arg_iterator it = Args.filtered_begin(OPT_c_isystem),
       ie = Args.filtered_end(); it != ie; ++it)
    Opts.AddPath((*it)->getValue(), frontend::CSystem, false, true);
  for (arg_iterator it = Args.filtered_begin(OPT_cxx_isystem),
       ie = Args.filtered_end(); it != ie; ++it)
    Opts.AddPath((*it)->getValue(), frontend::CXXSystem, false, true);
  for (arg_iterator it = Args.filtered_begin(OPT_objc_isystem),
       ie = Args.filtered_end(); it != ie; ++it)
    Opts.AddPath((*it)->getValue(), frontend::ObjCSystem, false,true);
  for (arg_iterator it = Args.filtered_begin(OPT_objcxx_isystem),
       ie = Args.filtered_end(); it != ie; ++it)
    Opts.AddPath((*it)->getValue(), frontend::ObjCXXSystem, false, true);

  // Add the internal paths from a driver that detects standard include paths.
  for (arg_iterator I = Args.filtered_begin(OPT_internal_isystem,
                                            OPT_internal_externc_isystem),
                    E = Args.filtered_end();
       I != E; ++I) {
    frontend::IncludeDirGroup Group = frontend::System;
    if ((*I)->getOption().matches(OPT_internal_externc_isystem))
      Group = frontend::ExternCSystem;
    Opts.AddPath((*I)->getValue(), Group, false, true);
  }

  // Add the path prefixes which are implicitly treated as being system headers.
  for (arg_iterator I = Args.filtered_begin(OPT_isystem_prefix,
                                            OPT_ino_system_prefix),
                    E = Args.filtered_end();
       I != E; ++I)
    Opts.AddSystemHeaderPrefix((*I)->getValue(),
                               (*I)->getOption().matches(OPT_isystem_prefix));
}

void CompilerInvocation::setLangDefaults(LangOptions &Opts, InputKind IK,
                                         LangStandard::Kind LangStd) {
  // Set some properties which depend solely on the input kind; it would be nice
  // to move these to the language standard, and have the driver resolve the
  // input kind + language standard.
  if (IK == IK_Asm) {
    Opts.AsmPreprocessor = 1;
  } else if (IK == IK_ObjC ||
             IK == IK_ObjCXX ||
             IK == IK_PreprocessedObjC ||
             IK == IK_PreprocessedObjCXX) {
    Opts.ObjC1 = Opts.ObjC2 = 1;
  }

  if (LangStd == LangStandard::lang_unspecified) {
    // Based on the base language, pick one.
    switch (IK) {
    case IK_None:
    case IK_AST:
    case IK_LLVM_IR:
      llvm_unreachable("Invalid input kind!");
    case IK_OpenCL:
      LangStd = LangStandard::lang_opencl;
      break;
    case IK_CUDA:
      LangStd = LangStandard::lang_cuda;
      break;
    case IK_Asm:
    case IK_C:
    case IK_PreprocessedC:
    case IK_ObjC:
    case IK_PreprocessedObjC:
      LangStd = LangStandard::lang_gnu99;
      break;
    case IK_CXX:
    case IK_PreprocessedCXX:
    case IK_ObjCXX:
    case IK_PreprocessedObjCXX:
      LangStd = LangStandard::lang_gnucxx98;
      break;
    }
  }

  const LangStandard &Std = LangStandard::getLangStandardForKind(LangStd);
  Opts.LineComment = Std.hasLineComments();
  Opts.C99 = Std.isC99();
  Opts.C11 = Std.isC11();
  Opts.CPlusPlus = Std.isCPlusPlus();
  Opts.CPlusPlus11 = Std.isCPlusPlus11();
  Opts.CPlusPlus1y = Std.isCPlusPlus1y();
  Opts.Digraphs = Std.hasDigraphs();
  Opts.GNUMode = Std.isGNUMode();
  Opts.GNUInline = !Std.isC99();
  Opts.HexFloats = Std.hasHexFloats();
  Opts.ImplicitInt = Std.hasImplicitInt();

  // Set OpenCL Version.
  if (LangStd == LangStandard::lang_opencl) {
    Opts.OpenCL = 1;
    Opts.OpenCLVersion = 100;
  }
  else if (LangStd == LangStandard::lang_opencl11) {
      Opts.OpenCL = 1;
      Opts.OpenCLVersion = 110;
  }
  else if (LangStd == LangStandard::lang_opencl12) {
    Opts.OpenCL = 1;
    Opts.OpenCLVersion = 120;
  }
  
  // OpenCL has some additional defaults.
  if (Opts.OpenCL) {
    Opts.AltiVec = 0;
    Opts.CXXOperatorNames = 1;
    Opts.LaxVectorConversions = 0;
    Opts.DefaultFPContract = 1;
    Opts.NativeHalfType = 1;
  }

  if (LangStd == LangStandard::lang_cuda)
    Opts.CUDA = 1;

  // OpenCL and C++ both have bool, true, false keywords.
  Opts.Bool = Opts.OpenCL || Opts.CPlusPlus;

  // C++ has wchar_t keyword.
  Opts.WChar = Opts.CPlusPlus;

  Opts.GNUKeywords = Opts.GNUMode;
  Opts.CXXOperatorNames = Opts.CPlusPlus;

  // Mimicing gcc's behavior, trigraphs are only enabled if -trigraphs
  // is specified, or -std is set to a conforming mode.
  Opts.Trigraphs = !Opts.GNUMode;

  Opts.DollarIdents = !Opts.AsmPreprocessor;
}

/// Attempt to parse a visibility value out of the given argument.
static Visibility parseVisibility(Arg *arg, ArgList &args,
                                  DiagnosticsEngine &diags) {
  StringRef value = arg->getValue();
  if (value == "default") {
    return DefaultVisibility;
  } else if (value == "hidden") {
    return HiddenVisibility;
  } else if (value == "protected") {
    // FIXME: diagnose if target does not support protected visibility
    return ProtectedVisibility;
  }

  diags.Report(diag::err_drv_invalid_value)
    << arg->getAsString(args) << value;
  return DefaultVisibility;
}

static void ParseLangArgs(LangOptions &Opts, ArgList &Args, InputKind IK,
                          DiagnosticsEngine &Diags) {
  // FIXME: Cleanup per-file based stuff.
  LangStandard::Kind LangStd = LangStandard::lang_unspecified;
  if (const Arg *A = Args.getLastArg(OPT_std_EQ)) {
    LangStd = llvm::StringSwitch<LangStandard::Kind>(A->getValue())
#define LANGSTANDARD(id, name, desc, features) \
      .Case(name, LangStandard::lang_##id)
#include "clang/Frontend/LangStandards.def"
      .Default(LangStandard::lang_unspecified);
    if (LangStd == LangStandard::lang_unspecified)
      Diags.Report(diag::err_drv_invalid_value)
        << A->getAsString(Args) << A->getValue();
    else {
      // Valid standard, check to make sure language and standard are compatable.    
      const LangStandard &Std = LangStandard::getLangStandardForKind(LangStd);
      switch (IK) {
      case IK_C:
      case IK_ObjC:
      case IK_PreprocessedC:
      case IK_PreprocessedObjC:
        if (!(Std.isC89() || Std.isC99()))
          Diags.Report(diag::err_drv_argument_not_allowed_with)
            << A->getAsString(Args) << "C/ObjC";
        break;
      case IK_CXX:
      case IK_ObjCXX:
      case IK_PreprocessedCXX:
      case IK_PreprocessedObjCXX:
        if (!Std.isCPlusPlus())
          Diags.Report(diag::err_drv_argument_not_allowed_with)
            << A->getAsString(Args) << "C++/ObjC++";
        break;
      case IK_OpenCL:
        if (!Std.isC99())
          Diags.Report(diag::err_drv_argument_not_allowed_with)
            << A->getAsString(Args) << "OpenCL";
        break;
      case IK_CUDA:
        if (!Std.isCPlusPlus())
          Diags.Report(diag::err_drv_argument_not_allowed_with)
            << A->getAsString(Args) << "CUDA";
        break;
      default:
        break;
      }
    }
  }

  // -cl-std only applies for OpenCL language standards.
  // Override the -std option in this case.
  if (const Arg *A = Args.getLastArg(OPT_cl_std_EQ)) {
    LangStandard::Kind OpenCLLangStd
    = llvm::StringSwitch<LangStandard::Kind>(A->getValue())
    .Case("CL", LangStandard::lang_opencl)
    .Case("CL1.1", LangStandard::lang_opencl11)
    .Case("CL1.2", LangStandard::lang_opencl12)
    .Default(LangStandard::lang_unspecified);
    
    if (OpenCLLangStd == LangStandard::lang_unspecified) {
      Diags.Report(diag::err_drv_invalid_value)
      << A->getAsString(Args) << A->getValue();
    }
    else
      LangStd = OpenCLLangStd;
  }
  
  CompilerInvocation::setLangDefaults(Opts, IK, LangStd);

  // We abuse '-f[no-]gnu-keywords' to force overriding all GNU-extension
  // keywords. This behavior is provided by GCC's poorly named '-fasm' flag,
  // while a subset (the non-C++ GNU keywords) is provided by GCC's
  // '-fgnu-keywords'. Clang conflates the two for simplicity under the single
  // name, as it doesn't seem a useful distinction.
  Opts.GNUKeywords = Args.hasFlag(OPT_fgnu_keywords, OPT_fno_gnu_keywords,
                                  Opts.GNUKeywords);

  if (Args.hasArg(OPT_fno_operator_names))
    Opts.CXXOperatorNames = 0;

  if (Opts.ObjC1) {
    if (Arg *arg = Args.getLastArg(OPT_fobjc_runtime_EQ)) {
      StringRef value = arg->getValue();
      if (Opts.ObjCRuntime.tryParse(value))
        Diags.Report(diag::err_drv_unknown_objc_runtime) << value;
    }

    if (Args.hasArg(OPT_fobjc_gc_only))
      Opts.setGC(LangOptions::GCOnly);
    else if (Args.hasArg(OPT_fobjc_gc))
      Opts.setGC(LangOptions::HybridGC);
    else if (Args.hasArg(OPT_fobjc_arc)) {
      Opts.ObjCAutoRefCount = 1;
      if (!Opts.ObjCRuntime.allowsARC())
        Diags.Report(diag::err_arc_unsupported_on_runtime);

      // Only set ObjCARCWeak if ARC is enabled.
      if (Args.hasArg(OPT_fobjc_runtime_has_weak))
        Opts.ObjCARCWeak = 1;
      else
        Opts.ObjCARCWeak = Opts.ObjCRuntime.allowsWeak();
    }

    if (Args.hasArg(OPT_fno_objc_infer_related_result_type))
      Opts.ObjCInferRelatedResultType = 0;
  }
    
  if (Args.hasArg(OPT_fgnu89_inline))
    Opts.GNUInline = 1;

  if (Args.hasArg(OPT_fapple_kext)) {
    if (!Opts.CPlusPlus)
      Diags.Report(diag::warn_c_kext);
    else
      Opts.AppleKext = 1;
  }

  if (Args.hasArg(OPT_print_ivar_layout))
    Opts.ObjCGCBitmapPrint = 1;
  if (Args.hasArg(OPT_fno_constant_cfstrings))
    Opts.NoConstantCFStrings = 1;

  if (Args.hasArg(OPT_faltivec))
    Opts.AltiVec = 1;

  if (Args.hasArg(OPT_pthread))
    Opts.POSIXThreads = 1;

  // The value-visibility mode defaults to "default".
  if (Arg *visOpt = Args.getLastArg(OPT_fvisibility)) {
    Opts.setValueVisibilityMode(parseVisibility(visOpt, Args, Diags));
  } else {
    Opts.setValueVisibilityMode(DefaultVisibility);
  }

  // The type-visibility mode defaults to the value-visibility mode.
  if (Arg *typeVisOpt = Args.getLastArg(OPT_ftype_visibility)) {
    Opts.setTypeVisibilityMode(parseVisibility(typeVisOpt, Args, Diags));
  } else {
    Opts.setTypeVisibilityMode(Opts.getValueVisibilityMode());
  }

  if (Args.hasArg(OPT_fvisibility_inlines_hidden))
    Opts.InlineVisibilityHidden = 1;

  if (Args.hasArg(OPT_ftrapv)) {
    Opts.setSignedOverflowBehavior(LangOptions::SOB_Trapping);
    // Set the handler, if one is specified.
    Opts.OverflowHandler =
        Args.getLastArgValue(OPT_ftrapv_handler);
  }
  else if (Args.hasArg(OPT_fwrapv))
    Opts.setSignedOverflowBehavior(LangOptions::SOB_Defined);

  if (Args.hasArg(OPT_trigraphs))
    Opts.Trigraphs = 1;

  Opts.DollarIdents = Args.hasFlag(OPT_fdollars_in_identifiers,
                                   OPT_fno_dollars_in_identifiers,
                                   Opts.DollarIdents);
  Opts.PascalStrings = Args.hasArg(OPT_fpascal_strings);
  Opts.MicrosoftExt
    = Args.hasArg(OPT_fms_extensions) || Args.hasArg(OPT_fms_compatibility);
  Opts.MicrosoftMode = Args.hasArg(OPT_fms_compatibility);
  Opts.AsmBlocks = Args.hasArg(OPT_fasm_blocks) || Opts.MicrosoftExt;
  Opts.MSCVersion = getLastArgIntValue(Args, OPT_fmsc_version, 0, Diags);
  Opts.Borland = Args.hasArg(OPT_fborland_extensions);
  Opts.WritableStrings = Args.hasArg(OPT_fwritable_strings);
  Opts.ConstStrings = Args.hasFlag(OPT_fconst_strings, OPT_fno_const_strings,
                                   Opts.ConstStrings);
  if (Args.hasArg(OPT_fno_lax_vector_conversions))
    Opts.LaxVectorConversions = 0;
  if (Args.hasArg(OPT_fno_threadsafe_statics))
    Opts.ThreadsafeStatics = 0;
  Opts.Exceptions = Args.hasArg(OPT_fexceptions);
  Opts.ObjCExceptions = Args.hasArg(OPT_fobjc_exceptions);
  Opts.CXXExceptions = Args.hasArg(OPT_fcxx_exceptions);
  Opts.SjLjExceptions = Args.hasArg(OPT_fsjlj_exceptions);
  Opts.TraditionalCPP = Args.hasArg(OPT_traditional_cpp);

  Opts.RTTI = !Args.hasArg(OPT_fno_rtti);
  Opts.Blocks = Args.hasArg(OPT_fblocks);
  Opts.BlocksRuntimeOptional = Args.hasArg(OPT_fblocks_runtime_optional);
  Opts.Modules = Args.hasArg(OPT_fmodules);
  Opts.CharIsSigned = !Args.hasArg(OPT_fno_signed_char);
  Opts.WChar = Opts.CPlusPlus && !Args.hasArg(OPT_fno_wchar);
  Opts.ShortWChar = Args.hasArg(OPT_fshort_wchar);
  Opts.ShortEnums = Args.hasArg(OPT_fshort_enums);
  Opts.Freestanding = Args.hasArg(OPT_ffreestanding);
  Opts.NoBuiltin = Args.hasArg(OPT_fno_builtin) || Opts.Freestanding;
  Opts.AssumeSaneOperatorNew = !Args.hasArg(OPT_fno_assume_sane_operator_new);
  Opts.HeinousExtensions = Args.hasArg(OPT_fheinous_gnu_extensions);
  Opts.AccessControl = !Args.hasArg(OPT_fno_access_control);
  Opts.ElideConstructors = !Args.hasArg(OPT_fno_elide_constructors);
  Opts.MathErrno = Args.hasArg(OPT_fmath_errno);
  Opts.InstantiationDepth =
      getLastArgIntValue(Args, OPT_ftemplate_depth, 256, Diags);
  Opts.ConstexprCallDepth =
      getLastArgIntValue(Args, OPT_fconstexpr_depth, 512, Diags);
  Opts.ConstexprStepLimit =
      getLastArgIntValue(Args, OPT_fconstexpr_steps, 1048576, Diags);
  Opts.BracketDepth = getLastArgIntValue(Args, OPT_fbracket_depth, 256, Diags);
  Opts.DelayedTemplateParsing = Args.hasArg(OPT_fdelayed_template_parsing);
  Opts.NumLargeByValueCopy =
      getLastArgIntValue(Args, OPT_Wlarge_by_value_copy_EQ, 0, Diags);
  Opts.MSBitfields = Args.hasArg(OPT_mms_bitfields);
  Opts.ObjCConstantStringClass =
    Args.getLastArgValue(OPT_fconstant_string_class);
  Opts.ObjCDefaultSynthProperties =
    Args.hasArg(OPT_fobjc_default_synthesize_properties);
  Opts.EncodeExtendedBlockSig =
    Args.hasArg(OPT_fencode_extended_block_signature);
  Opts.EmitAllDecls = Args.hasArg(OPT_femit_all_decls);
  Opts.PackStruct = getLastArgIntValue(Args, OPT_fpack_struct_EQ, 0, Diags);
  Opts.PICLevel = getLastArgIntValue(Args, OPT_pic_level, 0, Diags);
  Opts.PIELevel = getLastArgIntValue(Args, OPT_pie_level, 0, Diags);
  Opts.Static = Args.hasArg(OPT_static_define);
  Opts.DumpRecordLayoutsSimple = Args.hasArg(OPT_fdump_record_layouts_simple);
  Opts.DumpRecordLayouts = Opts.DumpRecordLayoutsSimple 
                        || Args.hasArg(OPT_fdump_record_layouts);
  Opts.DumpVTableLayouts = Args.hasArg(OPT_fdump_vtable_layouts);
  Opts.SpellChecking = !Args.hasArg(OPT_fno_spell_checking);
  Opts.NoBitFieldTypeAlign = Args.hasArg(OPT_fno_bitfield_type_align);
  Opts.SinglePrecisionConstants = Args.hasArg(OPT_cl_single_precision_constant);
  Opts.FastRelaxedMath = Args.hasArg(OPT_cl_fast_relaxed_math);
  Opts.MRTD = Args.hasArg(OPT_mrtd);
  Opts.HexagonQdsp6Compat = Args.hasArg(OPT_mqdsp6_compat);
  Opts.FakeAddressSpaceMap = Args.hasArg(OPT_ffake_address_space_map);
  Opts.ParseUnknownAnytype = Args.hasArg(OPT_funknown_anytype);
  Opts.DebuggerSupport = Args.hasArg(OPT_fdebugger_support);
  Opts.DebuggerCastResultToId = Args.hasArg(OPT_fdebugger_cast_result_to_id);
  Opts.DebuggerObjCLiteral = Args.hasArg(OPT_fdebugger_objc_literal);
  Opts.ApplePragmaPack = Args.hasArg(OPT_fapple_pragma_pack);
  Opts.CurrentModule = Args.getLastArgValue(OPT_fmodule_name);

  // Check if -fopenmp is specified.
  Opts.OpenMP = Args.hasArg(OPT_fopenmp);

  // Record whether the __DEPRECATED define was requested.
  Opts.Deprecated = Args.hasFlag(OPT_fdeprecated_macro,
                                 OPT_fno_deprecated_macro,
                                 Opts.Deprecated);

  // FIXME: Eliminate this dependency.
  unsigned Opt = getOptimizationLevel(Args, IK, Diags),
       OptSize = getOptimizationLevelSize(Args);
  Opts.Optimize = Opt != 0;
  Opts.OptimizeSize = OptSize != 0;

  // This is the __NO_INLINE__ define, which just depends on things like the
  // optimization level and -fno-inline, not actually whether the backend has
  // inlining enabled.
  Opts.NoInlineDefine = !Opt || Args.hasArg(OPT_fno_inline);

  Opts.FastMath = Args.hasArg(OPT_ffast_math);
  Opts.FiniteMathOnly = Args.hasArg(OPT_ffinite_math_only);

  Opts.RetainCommentsFromSystemHeaders =
      Args.hasArg(OPT_fretain_comments_from_system_headers);

  unsigned SSP = getLastArgIntValue(Args, OPT_stack_protector, 0, Diags);
  switch (SSP) {
  default:
    Diags.Report(diag::err_drv_invalid_value)
      << Args.getLastArg(OPT_stack_protector)->getAsString(Args) << SSP;
    break;
  case 0: Opts.setStackProtector(LangOptions::SSPOff); break;
  case 1: Opts.setStackProtector(LangOptions::SSPOn);  break;
  case 2: Opts.setStackProtector(LangOptions::SSPReq); break;
  }

  // Parse -fsanitize= arguments.
  std::vector<std::string> Sanitizers = Args.getAllArgValues(OPT_fsanitize_EQ);
  for (unsigned I = 0, N = Sanitizers.size(); I != N; ++I) {
    // Since the Opts.Sanitize* values are bitfields, it's a little tricky to
    // efficiently map string values to them. Perform the mapping indirectly:
    // convert strings to enumerated values, then switch over the enum to set
    // the right bitfield value.
    enum Sanitizer {
#define SANITIZER(NAME, ID) \
      ID,
#include "clang/Basic/Sanitizers.def"
      Unknown
    };
    switch (llvm::StringSwitch<unsigned>(Sanitizers[I])
#define SANITIZER(NAME, ID) \
              .Case(NAME, ID)
#include "clang/Basic/Sanitizers.def"
              .Default(Unknown)) {
#define SANITIZER(NAME, ID) \
    case ID: \
      Opts.Sanitize.ID = true; \
      break;
#include "clang/Basic/Sanitizers.def"

    case Unknown:
      Diags.Report(diag::err_drv_invalid_value)
        << "-fsanitize=" << Sanitizers[I];
      break;
    }
  }
}

static void ParsePreprocessorArgs(PreprocessorOptions &Opts, ArgList &Args,
                                  FileManager &FileMgr,
                                  DiagnosticsEngine &Diags) {
  using namespace options;
  Opts.ImplicitPCHInclude = Args.getLastArgValue(OPT_include_pch);
  Opts.ImplicitPTHInclude = Args.getLastArgValue(OPT_include_pth);
  if (const Arg *A = Args.getLastArg(OPT_token_cache))
      Opts.TokenCache = A->getValue();
  else
    Opts.TokenCache = Opts.ImplicitPTHInclude;
  Opts.UsePredefines = !Args.hasArg(OPT_undef);
  Opts.DetailedRecord = Args.hasArg(OPT_detailed_preprocessing_record);
  Opts.DisablePCHValidation = Args.hasArg(OPT_fno_validate_pch);

  Opts.DumpDeserializedPCHDecls = Args.hasArg(OPT_dump_deserialized_pch_decls);
  for (arg_iterator it = Args.filtered_begin(OPT_error_on_deserialized_pch_decl),
         ie = Args.filtered_end(); it != ie; ++it) {
    const Arg *A = *it;
    Opts.DeserializedPCHDeclsToErrorOn.insert(A->getValue());
  }

  if (const Arg *A = Args.getLastArg(OPT_preamble_bytes_EQ)) {
    StringRef Value(A->getValue());
    size_t Comma = Value.find(',');
    unsigned Bytes = 0;
    unsigned EndOfLine = 0;

    if (Comma == StringRef::npos ||
        Value.substr(0, Comma).getAsInteger(10, Bytes) ||
        Value.substr(Comma + 1).getAsInteger(10, EndOfLine))
      Diags.Report(diag::err_drv_preamble_format);
    else {
      Opts.PrecompiledPreambleBytes.first = Bytes;
      Opts.PrecompiledPreambleBytes.second = (EndOfLine != 0);
    }
  }

  // Add macros from the command line.
  for (arg_iterator it = Args.filtered_begin(OPT_D, OPT_U),
         ie = Args.filtered_end(); it != ie; ++it) {
    if ((*it)->getOption().matches(OPT_D))
      Opts.addMacroDef((*it)->getValue());
    else
      Opts.addMacroUndef((*it)->getValue());
  }

  Opts.MacroIncludes = Args.getAllArgValues(OPT_imacros);

  // Add the ordered list of -includes.
  for (arg_iterator it = Args.filtered_begin(OPT_include),
         ie = Args.filtered_end(); it != ie; ++it) {
    const Arg *A = *it;
    Opts.Includes.push_back(A->getValue());
  }

  for (arg_iterator it = Args.filtered_begin(OPT_chain_include),
         ie = Args.filtered_end(); it != ie; ++it) {
    const Arg *A = *it;
    Opts.ChainedIncludes.push_back(A->getValue());
  }

  // Include 'altivec.h' if -faltivec option present
  if (Args.hasArg(OPT_faltivec))
    Opts.Includes.push_back("altivec.h");

  for (arg_iterator it = Args.filtered_begin(OPT_remap_file),
         ie = Args.filtered_end(); it != ie; ++it) {
    const Arg *A = *it;
    std::pair<StringRef,StringRef> Split =
      StringRef(A->getValue()).split(';');

    if (Split.second.empty()) {
      Diags.Report(diag::err_drv_invalid_remap_file) << A->getAsString(Args);
      continue;
    }

    Opts.addRemappedFile(Split.first, Split.second);
  }
  
  if (Arg *A = Args.getLastArg(OPT_fobjc_arc_cxxlib_EQ)) {
    StringRef Name = A->getValue();
    unsigned Library = llvm::StringSwitch<unsigned>(Name)
      .Case("libc++", ARCXX_libcxx)
      .Case("libstdc++", ARCXX_libstdcxx)
      .Case("none", ARCXX_nolib)
      .Default(~0U);
    if (Library == ~0U)
      Diags.Report(diag::err_drv_invalid_value) << A->getAsString(Args) << Name;
    else
      Opts.ObjCXXARCStandardLibrary = (ObjCXXARCStandardLibraryKind)Library;
  }
}

static void ParsePreprocessorOutputArgs(PreprocessorOutputOptions &Opts,
                                        ArgList &Args,
                                        frontend::ActionKind Action) {
  using namespace options;

  switch (Action) {
  case frontend::ASTDeclList:
  case frontend::ASTDump:
  case frontend::ASTDumpXML:
  case frontend::ASTPrint:
  case frontend::ASTView:
  case frontend::EmitAssembly:
  case frontend::EmitBC:
  case frontend::EmitHTML:
  case frontend::EmitLLVM:
  case frontend::EmitLLVMOnly:
  case frontend::EmitCodeGenOnly:
  case frontend::EmitObj:
  case frontend::FixIt:
  case frontend::GenerateModule:
  case frontend::GeneratePCH:
  case frontend::GeneratePTH:
  case frontend::ParseSyntaxOnly:
  case frontend::ModuleFileInfo:
  case frontend::PluginAction:
  case frontend::PrintDeclContext:
  case frontend::RewriteObjC:
  case frontend::RewriteTest:
  case frontend::RunAnalysis:
  case frontend::MigrateSource:
    Opts.ShowCPP = 0;
    break;

  case frontend::DumpRawTokens:
  case frontend::DumpTokens:
  case frontend::InitOnly:
  case frontend::PrintPreamble:
  case frontend::PrintPreprocessedInput:
  case frontend::RewriteMacros:
  case frontend::RunPreprocessorOnly:
    Opts.ShowCPP = !Args.hasArg(OPT_dM);
    break;
  }

  Opts.ShowComments = Args.hasArg(OPT_C);
  Opts.ShowLineMarkers = !Args.hasArg(OPT_P);
  Opts.ShowMacroComments = Args.hasArg(OPT_CC);
  Opts.ShowMacros = Args.hasArg(OPT_dM) || Args.hasArg(OPT_dD);
  Opts.RewriteIncludes = Args.hasArg(OPT_frewrite_includes);
}

static void ParseTargetArgs(TargetOptions &Opts, ArgList &Args) {
  using namespace options;
  Opts.ABI = Args.getLastArgValue(OPT_target_abi);
  Opts.CXXABI = Args.getLastArgValue(OPT_cxx_abi);
  Opts.CPU = Args.getLastArgValue(OPT_target_cpu);
  Opts.FeaturesAsWritten = Args.getAllArgValues(OPT_target_feature);
  Opts.LinkerVersion = Args.getLastArgValue(OPT_target_linker_version);
  Opts.Triple = llvm::Triple::normalize(Args.getLastArgValue(OPT_triple));

  // Use the default target triple if unspecified.
  if (Opts.Triple.empty())
    Opts.Triple = llvm::sys::getDefaultTargetTriple();
}

//

bool CompilerInvocation::CreateFromArgs(CompilerInvocation &Res,
                                        const char *const *ArgBegin,
                                        const char *const *ArgEnd,
                                        DiagnosticsEngine &Diags) {
  bool Success = true;

  // Parse the arguments.
  OwningPtr<OptTable> Opts(createDriverOptTable());
  unsigned MissingArgIndex, MissingArgCount;
  OwningPtr<InputArgList> Args(
    Opts->ParseArgs(ArgBegin, ArgEnd,MissingArgIndex, MissingArgCount));

  // Check for missing argument error.
  if (MissingArgCount) {
    Diags.Report(diag::err_drv_missing_argument)
      << Args->getArgString(MissingArgIndex) << MissingArgCount;
    Success = false;
  }

  // Issue errors on unknown arguments.
  for (arg_iterator it = Args->filtered_begin(OPT_UNKNOWN),
         ie = Args->filtered_end(); it != ie; ++it) {
    Diags.Report(diag::err_drv_unknown_argument) << (*it)->getAsString(*Args);
    Success = false;
  }

  // Issue errors on arguments that are not valid for CC1.
  for (ArgList::iterator I = Args->begin(), E = Args->end();
       I != E; ++I) {
    if ((*I)->getOption().matches(options::OPT_INPUT))
      continue;
    if (!(*I)->getOption().hasFlag(options::CC1Option)) {
      Diags.Report(diag::err_drv_unknown_argument) << (*I)->getAsString(*Args);
      Success = false;
    }
  }

  Success = ParseAnalyzerArgs(*Res.getAnalyzerOpts(), *Args, Diags) && Success;
  Success = ParseMigratorArgs(Res.getMigratorOpts(), *Args) && Success;
  ParseDependencyOutputArgs(Res.getDependencyOutputOpts(), *Args);
  Success = ParseDiagnosticArgs(Res.getDiagnosticOpts(), *Args, &Diags)
            && Success;
  ParseCommentArgs(Res.getLangOpts()->CommentOpts, *Args);
  ParseFileSystemArgs(Res.getFileSystemOpts(), *Args);
  // FIXME: We shouldn't have to pass the DashX option around here
  InputKind DashX = ParseFrontendArgs(Res.getFrontendOpts(), *Args, Diags);
  Success = ParseCodeGenArgs(Res.getCodeGenOpts(), *Args, DashX, Diags)
            && Success;
  ParseHeaderSearchArgs(Res.getHeaderSearchOpts(), *Args);
  if (DashX != IK_AST && DashX != IK_LLVM_IR) {
    ParseLangArgs(*Res.getLangOpts(), *Args, DashX, Diags);
    if (Res.getFrontendOpts().ProgramAction == frontend::RewriteObjC)
      Res.getLangOpts()->ObjCExceptions = 1;
  }
  // FIXME: ParsePreprocessorArgs uses the FileManager to read the contents of
  // PCH file and find the original header name. Remove the need to do that in
  // ParsePreprocessorArgs and remove the FileManager 
  // parameters from the function and the "FileManager.h" #include.
  FileManager FileMgr(Res.getFileSystemOpts());
  ParsePreprocessorArgs(Res.getPreprocessorOpts(), *Args, FileMgr, Diags);
  ParsePreprocessorOutputArgs(Res.getPreprocessorOutputOpts(), *Args,
                              Res.getFrontendOpts().ProgramAction);
  ParseTargetArgs(Res.getTargetOpts(), *Args);

  return Success;
}

namespace {

  class ModuleSignature {
    SmallVector<uint64_t, 16> Data;
    unsigned CurBit;
    uint64_t CurValue;
    
  public:
    ModuleSignature() : CurBit(0), CurValue(0) { }
    
    void add(uint64_t Value, unsigned Bits);
    void add(StringRef Value);
    void flush();
    
    llvm::APInt getAsInteger() const;
  };
}

void ModuleSignature::add(uint64_t Value, unsigned int NumBits) {
  CurValue |= Value << CurBit;
  if (CurBit + NumBits < 64) {
    CurBit += NumBits;
    return;
  }
  
  // Add the current word.
  Data.push_back(CurValue);
  
  if (CurBit)
    CurValue = Value >> (64-CurBit);
  else
    CurValue = 0;
  CurBit = (CurBit+NumBits) & 63;
}

void ModuleSignature::flush() {
  if (CurBit == 0)
    return;
  
  Data.push_back(CurValue);
  CurBit = 0;
  CurValue = 0;
}

void ModuleSignature::add(StringRef Value) {
  for (StringRef::iterator I = Value.begin(), IEnd = Value.end(); I != IEnd;++I)
    add(*I, 8);
}

llvm::APInt ModuleSignature::getAsInteger() const {
  return llvm::APInt(Data.size() * 64, Data);
}

std::string CompilerInvocation::getModuleHash() const {
  // Note: For QoI reasons, the things we use as a hash here should all be
  // dumped via the -module-info flag.
  using llvm::hash_code;
  using llvm::hash_value;
  using llvm::hash_combine;

  // Start the signature with the compiler version.
  // FIXME: We'd rather use something more cryptographically sound than
  // CityHash, but this will do for now.
  hash_code code = hash_value(getClangFullRepositoryVersion());

  // Extend the signature with the language options
#define LANGOPT(Name, Bits, Default, Description) \
   code = hash_combine(code, LangOpts->Name);
#define ENUM_LANGOPT(Name, Type, Bits, Default, Description) \
  code = hash_combine(code, static_cast<unsigned>(LangOpts->get##Name()));
#define BENIGN_LANGOPT(Name, Bits, Default, Description)
#define BENIGN_ENUM_LANGOPT(Name, Type, Bits, Default, Description)
#include "clang/Basic/LangOptions.def"
  
  // Extend the signature with the target options.
  code = hash_combine(code, TargetOpts->Triple, TargetOpts->CPU,
                      TargetOpts->ABI, TargetOpts->CXXABI,
                      TargetOpts->LinkerVersion);
  for (unsigned i = 0, n = TargetOpts->FeaturesAsWritten.size(); i != n; ++i)
    code = hash_combine(code, TargetOpts->FeaturesAsWritten[i]);

  // Extend the signature with preprocessor options.
  const PreprocessorOptions &ppOpts = getPreprocessorOpts();
  const HeaderSearchOptions &hsOpts = getHeaderSearchOpts();
  code = hash_combine(code, ppOpts.UsePredefines, ppOpts.DetailedRecord);

  std::vector<StringRef> MacroDefs;
  for (std::vector<std::pair<std::string, bool/*isUndef*/> >::const_iterator 
            I = getPreprocessorOpts().Macros.begin(),
         IEnd = getPreprocessorOpts().Macros.end();
       I != IEnd; ++I) {
    // If we're supposed to ignore this macro for the purposes of modules,
    // don't put it into the hash.
    if (!hsOpts.ModulesIgnoreMacros.empty()) {
      // Check whether we're ignoring this macro.
      StringRef MacroDef = I->first;
      if (hsOpts.ModulesIgnoreMacros.count(MacroDef.split('=').first))
        continue;
    }

    code = hash_combine(code, I->first, I->second);
  }

  // Extend the signature with the sysroot.
  code = hash_combine(code, hsOpts.Sysroot, hsOpts.UseBuiltinIncludes,
                      hsOpts.UseStandardSystemIncludes,
                      hsOpts.UseStandardCXXIncludes,
                      hsOpts.UseLibcxx);

  // Darwin-specific hack: if we have a sysroot, use the contents and
  // modification time of
  //   $sysroot/System/Library/CoreServices/SystemVersion.plist
  // as part of the module hash.
  if (!hsOpts.Sysroot.empty()) {
    llvm::OwningPtr<llvm::MemoryBuffer> buffer;
    SmallString<128> systemVersionFile;
    systemVersionFile += hsOpts.Sysroot;
    llvm::sys::path::append(systemVersionFile, "System");
    llvm::sys::path::append(systemVersionFile, "Library");
    llvm::sys::path::append(systemVersionFile, "CoreServices");
    llvm::sys::path::append(systemVersionFile, "SystemVersion.plist");
    if (!llvm::MemoryBuffer::getFile(systemVersionFile, buffer)) {
      code = hash_combine(code, buffer.get()->getBuffer());

      struct stat statBuf;
      if (stat(systemVersionFile.c_str(), &statBuf) == 0)
        code = hash_combine(code, statBuf.st_mtime);
    }
  }

  return llvm::APInt(64, code).toString(36, /*Signed=*/false);
}

namespace clang {

// Declared in clang/Frontend/Utils.h.
int getLastArgIntValue(const ArgList &Args, OptSpecifier Id, int Default,
                       DiagnosticsEngine *Diags) {
  int Res = Default;
  if (Arg *A = Args.getLastArg(Id)) {
    if (StringRef(A->getValue()).getAsInteger(10, Res)) {
      if (Diags)
        Diags->Report(diag::err_drv_invalid_int_value) << A->getAsString(Args)
                                                       << A->getValue();
    }
  }
  return Res;
}
}

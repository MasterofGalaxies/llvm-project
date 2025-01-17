//===-- SymbolVendor.mm -----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "lldb/Symbol/SymbolVendor.h"

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes
#include "lldb/Core/Module.h"
#include "lldb/Core/PluginManager.h"
#include "lldb/Core/Stream.h"
#include "lldb/Symbol/CompileUnit.h"
#include "lldb/Symbol/ObjectFile.h"
#include "lldb/Symbol/SymbolFile.h"

using namespace lldb;
using namespace lldb_private;


//----------------------------------------------------------------------
// FindPlugin
//
// Platforms can register a callback to use when creating symbol
// vendors to allow for complex debug information file setups, and to
// also allow for finding separate debug information files.
//----------------------------------------------------------------------
SymbolVendor*
SymbolVendor::FindPlugin (const lldb::ModuleSP &module_sp, lldb_private::Stream *feedback_strm)
{
    std::unique_ptr<SymbolVendor> instance_ap;
    //----------------------------------------------------------------------
    // We currently only have one debug symbol parser...
    //----------------------------------------------------------------------
    SymbolVendorCreateInstance create_callback;
    for (size_t idx = 0; (create_callback = PluginManager::GetSymbolVendorCreateCallbackAtIndex(idx)) != NULL; ++idx)
    {
        instance_ap.reset(create_callback(module_sp, feedback_strm));

        if (instance_ap.get())
        {
            // TODO: make sure this symbol vendor is what we want. We
            // currently are just returning the first one we find, but
            // we may want to call this function only when we have our
            // main executable module and then give all symbol vendor
            // plug-ins a chance to compete for who wins.
            return instance_ap.release();
        }
    }
    // The default implementation just tries to create debug information using the
    // file representation for the module.
    instance_ap.reset(new SymbolVendor(module_sp));
    if (instance_ap.get())
    {
        ObjectFile *objfile = module_sp->GetObjectFile();
        if (objfile)
            instance_ap->AddSymbolFileRepresentation(objfile->shared_from_this());
    }
    return instance_ap.release();
}

//----------------------------------------------------------------------
// SymbolVendor constructor
//----------------------------------------------------------------------
SymbolVendor::SymbolVendor(const lldb::ModuleSP &module_sp) :
    ModuleChild (module_sp),
    m_type_list(),
    m_compile_units(),
    m_sym_file_ap()
{
}

//----------------------------------------------------------------------
// Destructor
//----------------------------------------------------------------------
SymbolVendor::~SymbolVendor()
{
}

//----------------------------------------------------------------------
// Add a represantion given an object file.
//----------------------------------------------------------------------
void
SymbolVendor::AddSymbolFileRepresentation(const ObjectFileSP &objfile_sp)
{
    ModuleSP module_sp(GetModule());
    if (module_sp)
    {
        lldb_private::Mutex::Locker locker(module_sp->GetMutex());
        if (objfile_sp)
        {
            m_objfile_sp = objfile_sp;
            m_sym_file_ap.reset(SymbolFile::FindPlugin(objfile_sp.get()));
        }
    }
}

bool
SymbolVendor::SetCompileUnitAtIndex (size_t idx, const CompUnitSP &cu_sp)
{
    ModuleSP module_sp(GetModule());
    if (module_sp)
    {
        lldb_private::Mutex::Locker locker(module_sp->GetMutex());
        const size_t num_compile_units = GetNumCompileUnits();
        if (idx < num_compile_units)
        {
            // Fire off an assertion if this compile unit already exists for now.
            // The partial parsing should take care of only setting the compile
            // unit once, so if this assertion fails, we need to make sure that
            // we don't have a race condition, or have a second parse of the same
            // compile unit.
            assert(m_compile_units[idx].get() == NULL);
            m_compile_units[idx] = cu_sp;
            return true;
        }
        else
        {
            // This should NOT happen, and if it does, we want to crash and know
            // about it
            assert (idx < num_compile_units);
        }
    }
    return false;
}

size_t
SymbolVendor::GetNumCompileUnits()
{
    ModuleSP module_sp(GetModule());
    if (module_sp)
    {
        lldb_private::Mutex::Locker locker(module_sp->GetMutex());
        if (m_compile_units.empty())
        {
            if (m_sym_file_ap.get())
            {
                // Resize our array of compile unit shared pointers -- which will
                // each remain NULL until someone asks for the actual compile unit
                // information. When this happens, the symbol file will be asked
                // to parse this compile unit information.
                m_compile_units.resize(m_sym_file_ap->GetNumCompileUnits());
            }
        }
    }
    return m_compile_units.size();
}

lldb::LanguageType
SymbolVendor::ParseCompileUnitLanguage (const SymbolContext& sc)
{
    ModuleSP module_sp(GetModule());
    if (module_sp)
    {
        lldb_private::Mutex::Locker locker(module_sp->GetMutex());
        if (m_sym_file_ap.get())
            return m_sym_file_ap->ParseCompileUnitLanguage(sc);
    }
    return eLanguageTypeUnknown;
}


size_t
SymbolVendor::ParseCompileUnitFunctions (const SymbolContext &sc)
{
    ModuleSP module_sp(GetModule());
    if (module_sp)
    {
        lldb_private::Mutex::Locker locker(module_sp->GetMutex());
        if (m_sym_file_ap.get())
            return m_sym_file_ap->ParseCompileUnitFunctions(sc);
    }
    return 0;
}

bool
SymbolVendor::ParseCompileUnitLineTable (const SymbolContext &sc)
{
    ModuleSP module_sp(GetModule());
    if (module_sp)
    {
        lldb_private::Mutex::Locker locker(module_sp->GetMutex());
        if (m_sym_file_ap.get())
            return m_sym_file_ap->ParseCompileUnitLineTable(sc);
    }
    return false;
}

bool
SymbolVendor::ParseCompileUnitSupportFiles (const SymbolContext& sc, FileSpecList& support_files)
{
    ModuleSP module_sp(GetModule());
    if (module_sp)
    {
        lldb_private::Mutex::Locker locker(module_sp->GetMutex());
        if (m_sym_file_ap.get())
            return m_sym_file_ap->ParseCompileUnitSupportFiles(sc, support_files);
    }
    return false;
}

size_t
SymbolVendor::ParseFunctionBlocks (const SymbolContext &sc)
{
    ModuleSP module_sp(GetModule());
    if (module_sp)
    {
        lldb_private::Mutex::Locker locker(module_sp->GetMutex());
        if (m_sym_file_ap.get())
            return m_sym_file_ap->ParseFunctionBlocks(sc);
    }
    return 0;
}

size_t
SymbolVendor::ParseTypes (const SymbolContext &sc)
{
    ModuleSP module_sp(GetModule());
    if (module_sp)
    {
        lldb_private::Mutex::Locker locker(module_sp->GetMutex());
        if (m_sym_file_ap.get())
            return m_sym_file_ap->ParseTypes(sc);
    }
    return 0;
}

size_t
SymbolVendor::ParseVariablesForContext (const SymbolContext& sc)
{
    ModuleSP module_sp(GetModule());
    if (module_sp)
    {
        lldb_private::Mutex::Locker locker(module_sp->GetMutex());
        if (m_sym_file_ap.get())
            return m_sym_file_ap->ParseVariablesForContext(sc);
    }
    return 0;
}

Type*
SymbolVendor::ResolveTypeUID(lldb::user_id_t type_uid)
{
    ModuleSP module_sp(GetModule());
    if (module_sp)
    {
        lldb_private::Mutex::Locker locker(module_sp->GetMutex());
        if (m_sym_file_ap.get())
            return m_sym_file_ap->ResolveTypeUID(type_uid);
    }
    return NULL;
}


uint32_t
SymbolVendor::ResolveSymbolContext (const Address& so_addr, uint32_t resolve_scope, SymbolContext& sc)
{
    ModuleSP module_sp(GetModule());
    if (module_sp)
    {
        lldb_private::Mutex::Locker locker(module_sp->GetMutex());
        if (m_sym_file_ap.get())
            return m_sym_file_ap->ResolveSymbolContext(so_addr, resolve_scope, sc);
    }
    return 0;
}

uint32_t
SymbolVendor::ResolveSymbolContext (const FileSpec& file_spec, uint32_t line, bool check_inlines, uint32_t resolve_scope, SymbolContextList& sc_list)
{
    ModuleSP module_sp(GetModule());
    if (module_sp)
    {
        lldb_private::Mutex::Locker locker(module_sp->GetMutex());
        if (m_sym_file_ap.get())
            return m_sym_file_ap->ResolveSymbolContext(file_spec, line, check_inlines, resolve_scope, sc_list);
    }
    return 0;
}

size_t
SymbolVendor::FindGlobalVariables (const ConstString &name, const ClangNamespaceDecl *namespace_decl, bool append, size_t max_matches, VariableList& variables)
{
    ModuleSP module_sp(GetModule());
    if (module_sp)
    {
        lldb_private::Mutex::Locker locker(module_sp->GetMutex());
        if (m_sym_file_ap.get())
            return m_sym_file_ap->FindGlobalVariables(name, namespace_decl, append, max_matches, variables);
    }
    return 0;
}

size_t
SymbolVendor::FindGlobalVariables (const RegularExpression& regex, bool append, size_t max_matches, VariableList& variables)
{
    ModuleSP module_sp(GetModule());
    if (module_sp)
    {
        lldb_private::Mutex::Locker locker(module_sp->GetMutex());
        if (m_sym_file_ap.get())
            return m_sym_file_ap->FindGlobalVariables(regex, append, max_matches, variables);
    }
    return 0;
}

size_t
SymbolVendor::FindFunctions(const ConstString &name, const ClangNamespaceDecl *namespace_decl, uint32_t name_type_mask, bool include_inlines, bool append, SymbolContextList& sc_list)
{
    ModuleSP module_sp(GetModule());
    if (module_sp)
    {
        lldb_private::Mutex::Locker locker(module_sp->GetMutex());
        if (m_sym_file_ap.get())
            return m_sym_file_ap->FindFunctions(name, namespace_decl, name_type_mask, include_inlines, append, sc_list);
    }
    return 0;
}

size_t
SymbolVendor::FindFunctions(const RegularExpression& regex, bool include_inlines, bool append, SymbolContextList& sc_list)
{
    ModuleSP module_sp(GetModule());
    if (module_sp)
    {
        lldb_private::Mutex::Locker locker(module_sp->GetMutex());
        if (m_sym_file_ap.get())
            return m_sym_file_ap->FindFunctions(regex, include_inlines, append, sc_list);
    }
    return 0;
}


size_t
SymbolVendor::FindTypes (const SymbolContext& sc, const ConstString &name, const ClangNamespaceDecl *namespace_decl, bool append, size_t max_matches, TypeList& types)
{
    ModuleSP module_sp(GetModule());
    if (module_sp)
    {
        lldb_private::Mutex::Locker locker(module_sp->GetMutex());
        if (m_sym_file_ap.get())
            return m_sym_file_ap->FindTypes(sc, name, namespace_decl, append, max_matches, types);
    }
    if (!append)
        types.Clear();
    return 0;
}

size_t
SymbolVendor::GetTypes (SymbolContextScope *sc_scope,
                        uint32_t type_mask,
                        lldb_private::TypeList &type_list)
{
    ModuleSP module_sp(GetModule());
    if (module_sp)
    {
        lldb_private::Mutex::Locker locker(module_sp->GetMutex());
        if (m_sym_file_ap.get())
            return m_sym_file_ap->GetTypes (sc_scope, type_mask, type_list);
    }
    return 0;
}

ClangNamespaceDecl
SymbolVendor::FindNamespace(const SymbolContext& sc, const ConstString &name, const ClangNamespaceDecl *parent_namespace_decl)
{
    ClangNamespaceDecl namespace_decl;
    ModuleSP module_sp(GetModule());
    if (module_sp)
    {
        lldb_private::Mutex::Locker locker(module_sp->GetMutex());
        if (m_sym_file_ap.get())
            namespace_decl = m_sym_file_ap->FindNamespace (sc, name, parent_namespace_decl);
    }
    return namespace_decl;
}

void
SymbolVendor::Dump(Stream *s)
{
    ModuleSP module_sp(GetModule());
    if (module_sp)
    {
        bool show_context = false;

        s->Printf("%p: ", this);
        s->Indent();
        s->PutCString("SymbolVendor");
        if (m_sym_file_ap.get())
        {
            ObjectFile *objfile = m_sym_file_ap->GetObjectFile();
            if (objfile)
            {
                const FileSpec &objfile_file_spec = objfile->GetFileSpec();
                if (objfile_file_spec)
                {
                    s->PutCString(" (");
                    objfile_file_spec.Dump(s);
                    s->PutChar(')');
                }
            }
        }
        s->EOL();
        s->IndentMore();
        m_type_list.Dump(s, show_context);

        CompileUnitConstIter cu_pos, cu_end;
        cu_end = m_compile_units.end();
        for (cu_pos = m_compile_units.begin(); cu_pos != cu_end; ++cu_pos)
        {
            // We currently only dump the compile units that have been parsed
            if (cu_pos->get())
                (*cu_pos)->Dump(s, show_context);
        }

        s->IndentLess();
    }
}

CompUnitSP
SymbolVendor::GetCompileUnitAtIndex(size_t idx)
{
    CompUnitSP cu_sp;
    ModuleSP module_sp(GetModule());
    if (module_sp)
    {
        const size_t num_compile_units = GetNumCompileUnits();
        if (idx < num_compile_units)
        {
            cu_sp = m_compile_units[idx];
            if (cu_sp.get() == NULL)
            {
                m_compile_units[idx] = m_sym_file_ap->ParseCompileUnitAtIndex(idx);
                cu_sp = m_compile_units[idx];
            }
        }
    }
    return cu_sp;
}


//------------------------------------------------------------------
// PluginInterface protocol
//------------------------------------------------------------------
lldb_private::ConstString
SymbolVendor::GetPluginName()
{
    static ConstString g_name("vendor-default");
    return g_name;
}

uint32_t
SymbolVendor::GetPluginVersion()
{
    return 1;
}


//===-- Address.cpp ---------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "lldb/Core/Address.h"
#include "lldb/Core/Module.h"
#include "lldb/Core/Section.h"
#include "lldb/Symbol/Block.h"
#include "lldb/Symbol/ObjectFile.h"
#include "lldb/Symbol/Type.h"
#include "lldb/Symbol/Variable.h"
#include "lldb/Symbol/VariableList.h"
#include "lldb/Target/ExecutionContext.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/Target.h"

#include "llvm/ADT/Triple.h"

using namespace lldb;
using namespace lldb_private;

static size_t
ReadBytes (ExecutionContextScope *exe_scope, const Address &address, void *dst, size_t dst_len)
{
    if (exe_scope == NULL)
        return 0;

    TargetSP target_sp (exe_scope->CalculateTarget());
    if (target_sp)
    {
        Error error;
        bool prefer_file_cache = false;
        return target_sp->ReadMemory (address, prefer_file_cache, dst, dst_len, error);
    }
    return 0;
}

static bool
GetByteOrderAndAddressSize (ExecutionContextScope *exe_scope, const Address &address, ByteOrder& byte_order, uint32_t& addr_size)
{
    byte_order = eByteOrderInvalid;
    addr_size = 0;
    if (exe_scope == NULL)
        return false;

    TargetSP target_sp (exe_scope->CalculateTarget());
    if (target_sp)
    {
        byte_order = target_sp->GetArchitecture().GetByteOrder();
        addr_size = target_sp->GetArchitecture().GetAddressByteSize();
    }

    if (byte_order == eByteOrderInvalid || addr_size == 0)
    {
        ModuleSP module_sp (address.GetModule());
        if (module_sp)
        {
            byte_order = module_sp->GetArchitecture().GetByteOrder();
            addr_size = module_sp->GetArchitecture().GetAddressByteSize();
        }
    }
    return byte_order != eByteOrderInvalid && addr_size != 0;
}

static uint64_t
ReadUIntMax64 (ExecutionContextScope *exe_scope, const Address &address, uint32_t byte_size, bool &success)
{
    uint64_t uval64 = 0;
    if (exe_scope == NULL || byte_size > sizeof(uint64_t))
    {
        success = false;
        return 0;
    }
    uint64_t buf = 0;

    success = ReadBytes (exe_scope, address, &buf, byte_size) == byte_size;
    if (success)
    {
        ByteOrder byte_order = eByteOrderInvalid;
        uint32_t addr_size = 0;
        if (GetByteOrderAndAddressSize (exe_scope, address, byte_order, addr_size))
        {
            DataExtractor data (&buf, sizeof(buf), byte_order, addr_size);
            lldb::offset_t offset = 0;
            uval64 = data.GetU64(&offset);
        }
        else
            success = false;
    }
    return uval64;
}

static bool
ReadAddress (ExecutionContextScope *exe_scope, const Address &address, uint32_t pointer_size, Address &deref_so_addr)
{
    if (exe_scope == NULL)
        return false;


    bool success = false;
    addr_t deref_addr = ReadUIntMax64 (exe_scope, address, pointer_size, success);
    if (success)
    {
        ExecutionContext exe_ctx;
        exe_scope->CalculateExecutionContext(exe_ctx);
        // If we have any sections that are loaded, try and resolve using the
        // section load list
        Target *target = exe_ctx.GetTargetPtr();
        if (target && !target->GetSectionLoadList().IsEmpty())
        {
            if (target->GetSectionLoadList().ResolveLoadAddress (deref_addr, deref_so_addr))
                return true;
        }
        else
        {
            // If we were not running, yet able to read an integer, we must
            // have a module
            ModuleSP module_sp (address.GetModule());

            assert (module_sp);
            if (module_sp->ResolveFileAddress(deref_addr, deref_so_addr))
                return true;
        }

        // We couldn't make "deref_addr" into a section offset value, but we were
        // able to read the address, so we return a section offset address with
        // no section and "deref_addr" as the offset (address).
        deref_so_addr.SetRawAddress(deref_addr);
        return true;
    }
    return false;
}

static bool
DumpUInt (ExecutionContextScope *exe_scope, const Address &address, uint32_t byte_size, Stream* strm)
{
    if (exe_scope == NULL || byte_size == 0)
        return 0;
    std::vector<uint8_t> buf(byte_size, 0);

    if (ReadBytes (exe_scope, address, &buf[0], buf.size()) == buf.size())
    {
        ByteOrder byte_order = eByteOrderInvalid;
        uint32_t addr_size = 0;
        if (GetByteOrderAndAddressSize (exe_scope, address, byte_order, addr_size))
        {
            DataExtractor data (&buf.front(), buf.size(), byte_order, addr_size);

            data.Dump (strm,
                       0,                 // Start offset in "data"
                       eFormatHex,        // Print as characters
                       buf.size(),        // Size of item
                       1,                 // Items count
                       UINT32_MAX,        // num per line
                       LLDB_INVALID_ADDRESS,// base address
                       0,                 // bitfield bit size
                       0);                // bitfield bit offset

            return true;
        }
    }
    return false;
}


static size_t
ReadCStringFromMemory (ExecutionContextScope *exe_scope, const Address &address, Stream *strm)
{
    if (exe_scope == NULL)
        return 0;
    const size_t k_buf_len = 256;
    char buf[k_buf_len+1];
    buf[k_buf_len] = '\0'; // NULL terminate

    // Byte order and address size don't matter for C string dumping..
    DataExtractor data (buf, sizeof(buf), lldb::endian::InlHostByteOrder(), 4);
    size_t total_len = 0;
    size_t bytes_read;
    Address curr_address(address);
    strm->PutChar ('"');
    while ((bytes_read = ReadBytes (exe_scope, curr_address, buf, k_buf_len)) > 0)
    {
        size_t len = strlen(buf);
        if (len == 0)
            break;
        if (len > bytes_read)
            len = bytes_read;

        data.Dump (strm,
                   0,                 // Start offset in "data"
                   eFormatChar,       // Print as characters
                   1,                 // Size of item (1 byte for a char!)
                   len,               // How many bytes to print?
                   UINT32_MAX,        // num per line
                   LLDB_INVALID_ADDRESS,// base address
                   0,                 // bitfield bit size

                   0);                // bitfield bit offset

        total_len += bytes_read;

        if (len < k_buf_len)
            break;
        curr_address.SetOffset (curr_address.GetOffset() + bytes_read);
    }
    strm->PutChar ('"');
    return total_len;
}

Address::Address (lldb::addr_t abs_addr) :
    m_section_wp (),
    m_offset (abs_addr)
{
}

Address::Address (addr_t address, const SectionList *section_list) :
    m_section_wp (),
    m_offset (LLDB_INVALID_ADDRESS)
{
    ResolveAddressUsingFileSections(address, section_list);
}

const Address&
Address::operator= (const Address& rhs)
{
    if (this != &rhs)
    {
        m_section_wp = rhs.m_section_wp;
        m_offset = rhs.m_offset.load();
    }
    return *this;
}

bool
Address::ResolveAddressUsingFileSections (addr_t file_addr, const SectionList *section_list)
{
    if (section_list)
    {
        SectionSP section_sp (section_list->FindSectionContainingFileAddress(file_addr));
        m_section_wp = section_sp;
        if (section_sp)
        {
            assert( section_sp->ContainsFileAddress(file_addr) );
            m_offset = file_addr - section_sp->GetFileAddress();
            return true;    // Successfully transformed addr into a section offset address
        }
    }
    m_offset = file_addr;
    return false;       // Failed to resolve this address to a section offset value
}

ModuleSP
Address::GetModule () const
{
    lldb::ModuleSP module_sp;
    SectionSP section_sp (GetSection());
    if (section_sp)
        module_sp = section_sp->GetModule();
    return module_sp;
}

addr_t
Address::GetFileAddress () const
{
    SectionSP section_sp (GetSection());
    if (section_sp)
    {
        addr_t sect_file_addr = section_sp->GetFileAddress();
        if (sect_file_addr == LLDB_INVALID_ADDRESS)
        {
            // Section isn't resolved, we can't return a valid file address
            return LLDB_INVALID_ADDRESS;
        }
        // We have a valid file range, so we can return the file based
        // address by adding the file base address to our offset
        return sect_file_addr + m_offset;
    }
    // No section, we just return the offset since it is the value in this case
    return m_offset;
}

addr_t
Address::GetLoadAddress (Target *target) const
{
    SectionSP section_sp (GetSection());
    if (!section_sp)
    {
        // No section, we just return the offset since it is the value in this case
        return m_offset;
    }
    
    if (target)
    {
        addr_t sect_load_addr = section_sp->GetLoadBaseAddress (target);

        if (sect_load_addr != LLDB_INVALID_ADDRESS)
        {
            // We have a valid file range, so we can return the file based
            // address by adding the file base address to our offset
            return sect_load_addr + m_offset;
        }
    }
    // The section isn't resolved or no process was supplied so we can't
    // return a valid file address.
    return LLDB_INVALID_ADDRESS;
}

addr_t
Address::GetCallableLoadAddress (Target *target, bool is_indirect) const
{
    if (is_indirect && target) {
        ProcessSP processSP = target->GetProcessSP();
        Error error;
        if (processSP.get())
            return processSP->ResolveIndirectFunction(this, error);
    }

    addr_t code_addr = GetLoadAddress (target);

    if (target)
        return target->GetCallableLoadAddress (code_addr, GetAddressClass());
    return code_addr;
}

bool
Address::SetCallableLoadAddress (lldb::addr_t load_addr, Target *target)
{
    if (SetLoadAddress (load_addr, target))
    {
        if (target)
            m_offset = target->GetCallableLoadAddress(m_offset, GetAddressClass());
        return true;
    }
    return false;
}

addr_t
Address::GetOpcodeLoadAddress (Target *target) const
{
    addr_t code_addr = GetLoadAddress (target);
    if (code_addr != LLDB_INVALID_ADDRESS)
        code_addr = target->GetOpcodeLoadAddress (code_addr, GetAddressClass());
    return code_addr;
}

bool
Address::SetOpcodeLoadAddress (lldb::addr_t load_addr, Target *target)
{
    if (SetLoadAddress (load_addr, target))
    {
        if (target)
            m_offset = target->GetOpcodeLoadAddress (m_offset, GetAddressClass());
        return true;
    }
    return false;
}

bool
Address::Dump (Stream *s, ExecutionContextScope *exe_scope, DumpStyle style, DumpStyle fallback_style, uint32_t addr_size) const
{
    // If the section was NULL, only load address is going to work unless we are
    // trying to deref a pointer
    SectionSP section_sp (GetSection());
    if (!section_sp && style != DumpStyleResolvedPointerDescription)
        style = DumpStyleLoadAddress;

    ExecutionContext exe_ctx (exe_scope);
    Target *target = exe_ctx.GetTargetPtr();
    // If addr_byte_size is UINT32_MAX, then determine the correct address
    // byte size for the process or default to the size of addr_t
    if (addr_size == UINT32_MAX)
    {
        if (target)
            addr_size = target->GetArchitecture().GetAddressByteSize ();
        else
            addr_size = sizeof(addr_t);
    }

    Address so_addr;
    switch (style)
    {
    case DumpStyleInvalid:
        return false;

    case DumpStyleSectionNameOffset:
        if (section_sp)
        {
            section_sp->DumpName(s);
            s->Printf (" + %" PRIu64, m_offset.load());
        }
        else
        {
            s->Address(m_offset, addr_size);
        }
        break;

    case DumpStyleSectionPointerOffset:
        s->Printf("(Section *)%p + ", section_sp.get());
        s->Address(m_offset, addr_size);
        break;

    case DumpStyleModuleWithFileAddress:
        if (section_sp)
            s->Printf("%s[", section_sp->GetModule()->GetFileSpec().GetFilename().AsCString());
        // Fall through
    case DumpStyleFileAddress:
        {
            addr_t file_addr = GetFileAddress();
            if (file_addr == LLDB_INVALID_ADDRESS)
            {
                if (fallback_style != DumpStyleInvalid)
                    return Dump (s, exe_scope, fallback_style, DumpStyleInvalid, addr_size);
                return false;
            }
            s->Address (file_addr, addr_size);
            if (style == DumpStyleModuleWithFileAddress && section_sp)
                s->PutChar(']');
        }
        break;

    case DumpStyleLoadAddress:
        {
            addr_t load_addr = GetLoadAddress (target);
            if (load_addr == LLDB_INVALID_ADDRESS)
            {
                if (fallback_style != DumpStyleInvalid)
                    return Dump (s, exe_scope, fallback_style, DumpStyleInvalid, addr_size);
                return false;
            }
            s->Address (load_addr, addr_size);
        }
        break;

    case DumpStyleResolvedDescription:
    case DumpStyleResolvedDescriptionNoModule:
        if (IsSectionOffset())
        {
            uint32_t pointer_size = 4;
            ModuleSP module_sp (GetModule());
            if (target)
                pointer_size = target->GetArchitecture().GetAddressByteSize();
            else if (module_sp)
                pointer_size = module_sp->GetArchitecture().GetAddressByteSize();

            bool showed_info = false;
            if (section_sp)
            {
                SectionType sect_type = section_sp->GetType();
                switch (sect_type)
                {
                case eSectionTypeData:
                    if (module_sp)
                    {
                        ObjectFile *objfile = module_sp->GetObjectFile();
                        if (objfile)
                        {
                            Symtab *symtab = objfile->GetSymtab();
                            if (symtab)
                            {
                                const addr_t file_Addr = GetFileAddress();
                                Symbol *symbol = symtab->FindSymbolContainingFileAddress (file_Addr);
                                if (symbol)
                                {
                                    const char *symbol_name = symbol->GetName().AsCString();
                                    if (symbol_name)
                                    {
                                        s->PutCString(symbol_name);
                                        addr_t delta = file_Addr - symbol->GetAddress().GetFileAddress();
                                        if (delta)
                                            s->Printf(" + %" PRIu64, delta);
                                        showed_info = true;
                                    }
                                }
                            }
                        }
                    }
                    break;

                case eSectionTypeDataCString:
                    // Read the C string from memory and display it
                    showed_info = true;
                    ReadCStringFromMemory (exe_scope, *this, s);
                    break;

                case eSectionTypeDataCStringPointers:
                    {
                        if (ReadAddress (exe_scope, *this, pointer_size, so_addr))
                        {
#if VERBOSE_OUTPUT
                            s->PutCString("(char *)");
                            so_addr.Dump(s, exe_scope, DumpStyleLoadAddress, DumpStyleFileAddress);
                            s->PutCString(": ");
#endif
                            showed_info = true;
                            ReadCStringFromMemory (exe_scope, so_addr, s);
                        }
                    }
                    break;

                case eSectionTypeDataObjCMessageRefs:
                    {
                        if (ReadAddress (exe_scope, *this, pointer_size, so_addr))
                        {
                            if (target && so_addr.IsSectionOffset())
                            {
                                SymbolContext func_sc;
                                target->GetImages().ResolveSymbolContextForAddress (so_addr,
                                                                                             eSymbolContextEverything,
                                                                                             func_sc);
                                if (func_sc.function || func_sc.symbol)
                                {
                                    showed_info = true;
#if VERBOSE_OUTPUT
                                    s->PutCString ("(objc_msgref *) -> { (func*)");
                                    so_addr.Dump(s, exe_scope, DumpStyleLoadAddress, DumpStyleFileAddress);
#else
                                    s->PutCString ("{ ");
#endif
                                    Address cstr_addr(*this);
                                    cstr_addr.SetOffset(cstr_addr.GetOffset() + pointer_size);
                                    func_sc.DumpStopContext(s, exe_scope, so_addr, true, true, false);
                                    if (ReadAddress (exe_scope, cstr_addr, pointer_size, so_addr))
                                    {
#if VERBOSE_OUTPUT
                                        s->PutCString("), (char *)");
                                        so_addr.Dump(s, exe_scope, DumpStyleLoadAddress, DumpStyleFileAddress);
                                        s->PutCString(" (");
#else
                                        s->PutCString(", ");
#endif
                                        ReadCStringFromMemory (exe_scope, so_addr, s);
                                    }
#if VERBOSE_OUTPUT
                                    s->PutCString(") }");
#else
                                    s->PutCString(" }");
#endif
                                }
                            }
                        }
                    }
                    break;

                case eSectionTypeDataObjCCFStrings:
                    {
                        Address cfstring_data_addr(*this);
                        cfstring_data_addr.SetOffset(cfstring_data_addr.GetOffset() + (2 * pointer_size));
                        if (ReadAddress (exe_scope, cfstring_data_addr, pointer_size, so_addr))
                        {
#if VERBOSE_OUTPUT
                            s->PutCString("(CFString *) ");
                            cfstring_data_addr.Dump(s, exe_scope, DumpStyleLoadAddress, DumpStyleFileAddress);
                            s->PutCString(" -> @");
#else
                            s->PutChar('@');
#endif
                            if (so_addr.Dump(s, exe_scope, DumpStyleResolvedDescription))
                                showed_info = true;
                        }
                    }
                    break;

                case eSectionTypeData4:
                    // Read the 4 byte data and display it
                    showed_info = true;
                    s->PutCString("(uint32_t) ");
                    DumpUInt (exe_scope, *this, 4, s);
                    break;

                case eSectionTypeData8:
                    // Read the 8 byte data and display it
                    showed_info = true;
                    s->PutCString("(uint64_t) ");
                    DumpUInt (exe_scope, *this, 8, s);
                    break;

                case eSectionTypeData16:
                    // Read the 16 byte data and display it
                    showed_info = true;
                    s->PutCString("(uint128_t) ");
                    DumpUInt (exe_scope, *this, 16, s);
                    break;

                case eSectionTypeDataPointers:
                    // Read the pointer data and display it
                    {
                        if (ReadAddress (exe_scope, *this, pointer_size, so_addr))
                        {
                            s->PutCString ("(void *)");
                            so_addr.Dump(s, exe_scope, DumpStyleLoadAddress, DumpStyleFileAddress);

                            showed_info = true;
                            if (so_addr.IsSectionOffset())
                            {
                                SymbolContext pointer_sc;
                                if (target)
                                {
                                    target->GetImages().ResolveSymbolContextForAddress (so_addr,
                                                                                                 eSymbolContextEverything,
                                                                                                 pointer_sc);
                                    if (pointer_sc.function || pointer_sc.symbol)
                                    {
                                        s->PutCString(": ");
                                        pointer_sc.DumpStopContext(s, exe_scope, so_addr, true, false, false);
                                    }
                                }
                            }
                        }
                    }
                    break;

                default:
                    break;
                }
            }

            if (!showed_info)
            {
                if (module_sp)
                {
                    SymbolContext sc;
                    module_sp->ResolveSymbolContextForAddress(*this, eSymbolContextEverything, sc);
                    if (sc.function || sc.symbol)
                    {
                        bool show_stop_context = true;
                        const bool show_module = (style == DumpStyleResolvedDescription);
                        const bool show_fullpaths = false; 
                        const bool show_inlined_frames = true;
                        if (sc.function == NULL && sc.symbol != NULL)
                        {
                            // If we have just a symbol make sure it is in the right section
                            if (sc.symbol->ValueIsAddress())
                            {
                                if (sc.symbol->GetAddress().GetSection() != GetSection())
                                {
                                    // don't show the module if the symbol is a trampoline symbol
                                    show_stop_context = false;
                                }
                            }
                        }
                        if (show_stop_context)
                        {
                            // We have a function or a symbol from the same
                            // sections as this address.
                            sc.DumpStopContext (s, 
                                                exe_scope, 
                                                *this, 
                                                show_fullpaths, 
                                                show_module, 
                                                show_inlined_frames);
                        }
                        else
                        {
                            // We found a symbol but it was in a different
                            // section so it isn't the symbol we should be
                            // showing, just show the section name + offset
                            Dump (s, exe_scope, DumpStyleSectionNameOffset);
                        }
                    }
                }
            }
        }
        else
        {
            if (fallback_style != DumpStyleInvalid)
                return Dump (s, exe_scope, fallback_style, DumpStyleInvalid, addr_size);
            return false;
        }
        break;

    case DumpStyleDetailedSymbolContext:
        if (IsSectionOffset())
        {
            ModuleSP module_sp (GetModule());
            if (module_sp)
            {
                SymbolContext sc;
                module_sp->ResolveSymbolContextForAddress(*this, eSymbolContextEverything, sc);
                if (sc.symbol)
                {
                    // If we have just a symbol make sure it is in the same section
                    // as our address. If it isn't, then we might have just found
                    // the last symbol that came before the address that we are 
                    // looking up that has nothing to do with our address lookup.
                    if (sc.symbol->ValueIsAddress() && sc.symbol->GetAddress().GetSection() != GetSection())
                        sc.symbol = NULL;
                }
                sc.GetDescription(s, eDescriptionLevelBrief, target);
                
                if (sc.block)
                {
                    bool can_create = true;
                    bool get_parent_variables = true;
                    bool stop_if_block_is_inlined_function = false;
                    VariableList variable_list;
                    sc.block->AppendVariables (can_create,
                                               get_parent_variables, 
                                               stop_if_block_is_inlined_function, 
                                               &variable_list);
                    
                    const size_t num_variables = variable_list.GetSize();
                    for (size_t var_idx = 0; var_idx < num_variables; ++var_idx)
                    {
                        Variable *var = variable_list.GetVariableAtIndex (var_idx).get();
                        if (var && var->LocationIsValidForAddress (*this))
                        {
                            s->Indent();
                            s->Printf ("   Variable: id = {0x%8.8" PRIx64 "}, name = \"%s\", type= \"%s\", location =",
                                       var->GetID(),
                                       var->GetName().GetCString(),
                                       var->GetType()->GetName().GetCString());
                            var->DumpLocationForAddress(s, *this);
                            s->PutCString(", decl = ");
                            var->GetDeclaration().DumpStopContext(s, false);
                            s->EOL();
                        }
                    }
                }
            }
        }
        else
        {
            if (fallback_style != DumpStyleInvalid)
                return Dump (s, exe_scope, fallback_style, DumpStyleInvalid, addr_size);
            return false;
        }
        break;
    case DumpStyleResolvedPointerDescription:
        {
            Process *process = exe_ctx.GetProcessPtr();
            if (process)
            {
                addr_t load_addr = GetLoadAddress (target);
                if (load_addr != LLDB_INVALID_ADDRESS)
                {
                    Error memory_error;
                    addr_t dereferenced_load_addr = process->ReadPointerFromMemory(load_addr, memory_error);
                    if (dereferenced_load_addr != LLDB_INVALID_ADDRESS)
                    {
                        Address dereferenced_addr;
                        if (dereferenced_addr.SetLoadAddress(dereferenced_load_addr, target))
                        {
                            StreamString strm;
                            if (dereferenced_addr.Dump (&strm, exe_scope, DumpStyleResolvedDescription, DumpStyleInvalid, addr_size))
                            {
                                s->Address (dereferenced_load_addr, addr_size, " -> ", " ");
                                s->Write(strm.GetData(), strm.GetSize());
                                return true;
                            }
                        }
                    }
                }
            }
            if (fallback_style != DumpStyleInvalid)
                return Dump (s, exe_scope, fallback_style, DumpStyleInvalid, addr_size);
            return false;
        }
        break;
    }

    return true;
}

uint32_t
Address::CalculateSymbolContext (SymbolContext *sc, uint32_t resolve_scope) const
{
    sc->Clear(false);
    // Absolute addresses don't have enough information to reconstruct even their target.

    SectionSP section_sp (GetSection());
    if (section_sp)
    {
        ModuleSP module_sp (section_sp->GetModule());
        if (module_sp)
        {
            sc->module_sp = module_sp;
            if (sc->module_sp)
                return sc->module_sp->ResolveSymbolContextForAddress (*this, resolve_scope, *sc);
        }
    }
    return 0;
}

ModuleSP
Address::CalculateSymbolContextModule () const
{
    SectionSP section_sp (GetSection());
    if (section_sp)
        return section_sp->GetModule();
    return ModuleSP();
}

CompileUnit *
Address::CalculateSymbolContextCompileUnit () const
{
    SectionSP section_sp (GetSection());
    if (section_sp)
    {
        SymbolContext sc;
        sc.module_sp = section_sp->GetModule();
        if (sc.module_sp)
        {
            sc.module_sp->ResolveSymbolContextForAddress (*this, eSymbolContextCompUnit, sc);
            return sc.comp_unit;
        }
    }
    return NULL;
}

Function *
Address::CalculateSymbolContextFunction () const
{
    SectionSP section_sp (GetSection());
    if (section_sp)
    {
        SymbolContext sc;
        sc.module_sp = section_sp->GetModule();
        if (sc.module_sp)
        {
            sc.module_sp->ResolveSymbolContextForAddress (*this, eSymbolContextFunction, sc);
            return sc.function;
        }
    }
    return NULL;
}

Block *
Address::CalculateSymbolContextBlock () const
{
    SectionSP section_sp (GetSection());
    if (section_sp)
    {
        SymbolContext sc;
        sc.module_sp = section_sp->GetModule();
        if (sc.module_sp)
        {
            sc.module_sp->ResolveSymbolContextForAddress (*this, eSymbolContextBlock, sc);
            return sc.block;
        }
    }
    return NULL;
}

Symbol *
Address::CalculateSymbolContextSymbol () const
{
    SectionSP section_sp (GetSection());
    if (section_sp)
    {
        SymbolContext sc;
        sc.module_sp = section_sp->GetModule();
        if (sc.module_sp)
        {
            sc.module_sp->ResolveSymbolContextForAddress (*this, eSymbolContextSymbol, sc);
            return sc.symbol;
        }
    }
    return NULL;
}

bool
Address::CalculateSymbolContextLineEntry (LineEntry &line_entry) const
{
    SectionSP section_sp (GetSection());
    if (section_sp)
    {
        SymbolContext sc;
        sc.module_sp = section_sp->GetModule();
        if (sc.module_sp)
        {
            sc.module_sp->ResolveSymbolContextForAddress (*this, eSymbolContextLineEntry, sc);
            if (sc.line_entry.IsValid())
            {
                line_entry = sc.line_entry;
                return true;
            }
        }
    }
    line_entry.Clear();
    return false;
}

int
Address::CompareFileAddress (const Address& a, const Address& b)
{
    addr_t a_file_addr = a.GetFileAddress();
    addr_t b_file_addr = b.GetFileAddress();
    if (a_file_addr < b_file_addr)
        return -1;
    if (a_file_addr > b_file_addr)
        return +1;
    return 0;
}


int
Address::CompareLoadAddress (const Address& a, const Address& b, Target *target)
{
    assert (target != NULL);
    addr_t a_load_addr = a.GetLoadAddress (target);
    addr_t b_load_addr = b.GetLoadAddress (target);
    if (a_load_addr < b_load_addr)
        return -1;
    if (a_load_addr > b_load_addr)
        return +1;
    return 0;
}

int
Address::CompareModulePointerAndOffset (const Address& a, const Address& b)
{
    ModuleSP a_module_sp (a.GetModule());
    ModuleSP b_module_sp (b.GetModule());
    Module *a_module = a_module_sp.get();
    Module *b_module = b_module_sp.get();
    if (a_module < b_module)
        return -1;
    if (a_module > b_module)
        return +1;
    // Modules are the same, just compare the file address since they should
    // be unique
    addr_t a_file_addr = a.GetFileAddress();
    addr_t b_file_addr = b.GetFileAddress();
    if (a_file_addr < b_file_addr)
        return -1;
    if (a_file_addr > b_file_addr)
        return +1;
    return 0;
}


size_t
Address::MemorySize () const
{
    // Noting special for the memory size of a single Address object,
    // it is just the size of itself.
    return sizeof(Address);
}


//----------------------------------------------------------------------
// NOTE: Be careful using this operator. It can correctly compare two 
// addresses from the same Module correctly. It can't compare two 
// addresses from different modules in any meaningful way, but it will
// compare the module pointers.
// 
// To sum things up:
// - works great for addresses within the same module
// - it works for addresses across multiple modules, but don't expect the
//   address results to make much sense
//
// This basically lets Address objects be used in ordered collection 
// classes.
//----------------------------------------------------------------------

bool
lldb_private::operator< (const Address& lhs, const Address& rhs)
{
    ModuleSP lhs_module_sp (lhs.GetModule());
    ModuleSP rhs_module_sp (rhs.GetModule());
    Module *lhs_module = lhs_module_sp.get();
    Module *rhs_module = rhs_module_sp.get();   
    if (lhs_module == rhs_module)
    {
        // Addresses are in the same module, just compare the file addresses
        return lhs.GetFileAddress() < rhs.GetFileAddress();
    }
    else
    {
        // The addresses are from different modules, just use the module
        // pointer value to get consistent ordering
        return lhs_module < rhs_module;
    }
}

bool
lldb_private::operator> (const Address& lhs, const Address& rhs)
{
    ModuleSP lhs_module_sp (lhs.GetModule());
    ModuleSP rhs_module_sp (rhs.GetModule());
    Module *lhs_module = lhs_module_sp.get();
    Module *rhs_module = rhs_module_sp.get();   
    if (lhs_module == rhs_module)
    {
        // Addresses are in the same module, just compare the file addresses
        return lhs.GetFileAddress() > rhs.GetFileAddress();
    }
    else
    {
        // The addresses are from different modules, just use the module
        // pointer value to get consistent ordering
        return lhs_module > rhs_module;
    }
}


// The operator == checks for exact equality only (same section, same offset)
bool
lldb_private::operator== (const Address& a, const Address& rhs)
{
    return  a.GetOffset()  == rhs.GetOffset() &&
            a.GetSection() == rhs.GetSection();
}
// The operator != checks for exact inequality only (differing section, or
// different offset)
bool
lldb_private::operator!= (const Address& a, const Address& rhs)
{
    return  a.GetOffset()  != rhs.GetOffset() ||
            a.GetSection() != rhs.GetSection();
}

AddressClass
Address::GetAddressClass () const
{
    ModuleSP module_sp (GetModule());
    if (module_sp)
    {
        ObjectFile *obj_file = module_sp->GetObjectFile();
        if (obj_file)
            return obj_file->GetAddressClass (GetFileAddress());
    }
    return eAddressClassUnknown;
}

bool
Address::SetLoadAddress (lldb::addr_t load_addr, Target *target)
{
    if (target && target->GetSectionLoadList().ResolveLoadAddress(load_addr, *this))
        return true;
    m_section_wp.reset();
    m_offset = load_addr;
    return false;
}


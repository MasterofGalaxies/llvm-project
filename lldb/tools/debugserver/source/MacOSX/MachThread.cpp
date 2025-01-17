//===-- MachThread.cpp ------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  Created by Greg Clayton on 6/19/07.
//
//===----------------------------------------------------------------------===//

#include <inttypes.h>
#include "MachThread.h"
#include "MachProcess.h"
#include "DNBLog.h"
#include "DNB.h"

static uint32_t
GetSequenceID()
{
    static uint32_t g_nextID = 0;
    return ++g_nextID;
}

MachThread::MachThread (MachProcess *process, uint64_t unique_thread_id, thread_t mach_port_num) :
    m_process (process),
    m_unique_id (unique_thread_id),
    m_mach_port_number (mach_port_num),
    m_seq_id (GetSequenceID()),
    m_state (eStateUnloaded),
    m_state_mutex (PTHREAD_MUTEX_RECURSIVE),
    m_suspend_count (0),
    m_stop_exception (),
    m_arch_ap (DNBArchProtocol::Create (this)),
    m_reg_sets (NULL),
    m_num_reg_sets (0), 
    m_ident_info(),
    m_proc_threadinfo(),
    m_dispatch_queue_name()
{
    nub_size_t num_reg_sets = 0;
    m_reg_sets = m_arch_ap->GetRegisterSetInfo (&num_reg_sets);
    m_num_reg_sets = num_reg_sets;

    // Get the thread state so we know if a thread is in a state where we can't
    // muck with it and also so we get the suspend count correct in case it was
    // already suspended
    GetBasicInfo();
    DNBLogThreadedIf(LOG_THREAD | LOG_VERBOSE, "MachThread::MachThread ( process = %p, tid = 0x%8.8" PRIx64 ", seq_id = %u )", &m_process, m_unique_id, m_seq_id);
}

MachThread::~MachThread()
{
    DNBLogThreadedIf(LOG_THREAD | LOG_VERBOSE, "MachThread::~MachThread() for tid = 0x%8.8" PRIx64 " (%u)", m_unique_id, m_seq_id);
}



void
MachThread::Suspend()
{
    DNBLogThreadedIf(LOG_THREAD | LOG_VERBOSE, "MachThread::%s ( )", __FUNCTION__);
    if (MachPortNumberIsValid(m_mach_port_number))
    {
        DNBError err(::thread_suspend (m_mach_port_number), DNBError::MachKernel);
        if (err.Success())
            m_suspend_count++;
        if (DNBLogCheckLogBit(LOG_THREAD) || err.Fail())
            err.LogThreaded("::thread_suspend (%4.4" PRIx32 ")", m_mach_port_number);
    }
}

void
MachThread::Resume(bool others_stopped)
{
    DNBLogThreadedIf(LOG_THREAD | LOG_VERBOSE, "MachThread::%s ( )", __FUNCTION__);
    if (MachPortNumberIsValid(m_mach_port_number))
    {
        SetSuspendCountBeforeResume(others_stopped);
    }
}

bool
MachThread::SetSuspendCountBeforeResume(bool others_stopped)
{
    DNBLogThreadedIf(LOG_THREAD | LOG_VERBOSE, "MachThread::%s ( )", __FUNCTION__);
    DNBError err;
    if (MachPortNumberIsValid(m_mach_port_number) == false)
        return false;
        
    size_t times_to_resume;
        
    if (others_stopped)
    {
        if (GetBasicInfo())
        {
            times_to_resume = m_basic_info.suspend_count;
            m_suspend_count = - (times_to_resume - m_suspend_count);
        }
        else
            times_to_resume = 0;
    }
    else
    {
        times_to_resume = m_suspend_count;
        m_suspend_count = 0;
    }

    if (times_to_resume > 0)
    {
        while (times_to_resume > 0)
        {
            err = ::thread_resume (m_mach_port_number);
            if (DNBLogCheckLogBit(LOG_THREAD) || err.Fail())
                err.LogThreaded("::thread_resume (%4.4" PRIx32 ")", m_mach_port_number);
            if (err.Success())
                --times_to_resume;
            else
            {
                if (GetBasicInfo())
                    times_to_resume = m_basic_info.suspend_count;
                else
                    times_to_resume = 0;
            }
        }
    }
    return true;
}

bool
MachThread::RestoreSuspendCountAfterStop ()
{
    DNBLogThreadedIf(LOG_THREAD | LOG_VERBOSE, "MachThread::%s ( )", __FUNCTION__);
    DNBError err;
    if (MachPortNumberIsValid(m_mach_port_number) == false)
        return false;
        
    if (m_suspend_count > 0)
    {
        while (m_suspend_count > 0)
        {
            err = ::thread_resume (m_mach_port_number);
            if (DNBLogCheckLogBit(LOG_THREAD) || err.Fail())
                err.LogThreaded("::thread_resume (%4.4" PRIx32 ")", m_mach_port_number);
            if (err.Success())
                --m_suspend_count;
            else
            {
                if (GetBasicInfo())
                    m_suspend_count = m_basic_info.suspend_count;
                else
                    m_suspend_count = 0;
                return false; // ??? 
            }
        }
    }
    else if (m_suspend_count < 0)
    {
        while (m_suspend_count < 0)
        {
            err = ::thread_suspend (m_mach_port_number);
            if (err.Success())
                ++m_suspend_count;
            if (DNBLogCheckLogBit(LOG_THREAD) || err.Fail())
            {
                err.LogThreaded("::thread_suspend (%4.4" PRIx32 ")", m_mach_port_number);
                return false;
            }
        }
    }
    return true;
}


const char *
MachThread::GetBasicInfoAsString () const
{
    static char g_basic_info_string[1024];
    struct thread_basic_info basicInfo;

    if (GetBasicInfo(m_mach_port_number, &basicInfo))
    {

//        char run_state_str[32];
//        size_t run_state_str_size = sizeof(run_state_str);
//        switch (basicInfo.run_state)
//        {
//        case TH_STATE_RUNNING:          strncpy(run_state_str, "running", run_state_str_size); break;
//        case TH_STATE_STOPPED:          strncpy(run_state_str, "stopped", run_state_str_size); break;
//        case TH_STATE_WAITING:          strncpy(run_state_str, "waiting", run_state_str_size); break;
//        case TH_STATE_UNINTERRUPTIBLE:  strncpy(run_state_str, "uninterruptible", run_state_str_size); break;
//        case TH_STATE_HALTED:           strncpy(run_state_str, "halted", run_state_str_size); break;
//        default:                        snprintf(run_state_str, run_state_str_size, "%d", basicInfo.run_state); break;    // ???
//        }
        float user = (float)basicInfo.user_time.seconds + (float)basicInfo.user_time.microseconds / 1000000.0f;
        float system = (float)basicInfo.user_time.seconds + (float)basicInfo.user_time.microseconds / 1000000.0f;
        snprintf(g_basic_info_string, sizeof(g_basic_info_string), "Thread 0x%8.8" PRIx64 ": user=%f system=%f cpu=%d sleep_time=%d",
            m_unique_id,
            user,
            system,
            basicInfo.cpu_usage,
            basicInfo.sleep_time);

        return g_basic_info_string;
    }
    return NULL;
}

// Finds the Mach port number for a given thread in the inferior process' port namespace.
thread_t
MachThread::InferiorThreadID() const
{
    mach_msg_type_number_t i;
    mach_port_name_array_t names;
    mach_port_type_array_t types;
    mach_msg_type_number_t ncount, tcount;
    thread_t inferior_tid = INVALID_NUB_THREAD;
    task_t my_task = ::mach_task_self();
    task_t task = m_process->Task().TaskPort();

    kern_return_t kret = ::mach_port_names (task, &names, &ncount, &types, &tcount);
    if (kret == KERN_SUCCESS)
    {

        for (i = 0; i < ncount; i++)
        {
            mach_port_t my_name;
            mach_msg_type_name_t my_type;

            kret = ::mach_port_extract_right (task, names[i], MACH_MSG_TYPE_COPY_SEND, &my_name, &my_type);
            if (kret == KERN_SUCCESS)
            {
                ::mach_port_deallocate (my_task, my_name);
                if (my_name == m_mach_port_number)
                {
                    inferior_tid = names[i];
                    break;
                }
            }
        }
        // Free up the names and types
        ::vm_deallocate (my_task, (vm_address_t) names, ncount * sizeof (mach_port_name_t));
        ::vm_deallocate (my_task, (vm_address_t) types, tcount * sizeof (mach_port_type_t));
    }
    return inferior_tid;
}

bool
MachThread::IsUserReady()
{
    if (m_basic_info.run_state == 0)
        GetBasicInfo ();
    
    switch (m_basic_info.run_state)
    {
    default: 
    case TH_STATE_UNINTERRUPTIBLE:  
        break;

    case TH_STATE_RUNNING:
    case TH_STATE_STOPPED:
    case TH_STATE_WAITING:
    case TH_STATE_HALTED:
        return true;
    }
    return false;
}

struct thread_basic_info *
MachThread::GetBasicInfo ()
{
    if (MachThread::GetBasicInfo(m_mach_port_number, &m_basic_info))
        return &m_basic_info;
    return NULL;
}


bool
MachThread::GetBasicInfo(thread_t thread, struct thread_basic_info *basicInfoPtr)
{
    if (MachPortNumberIsValid(thread))
    {
        unsigned int info_count = THREAD_BASIC_INFO_COUNT;
        kern_return_t err = ::thread_info (thread, THREAD_BASIC_INFO, (thread_info_t) basicInfoPtr, &info_count);
        if (err == KERN_SUCCESS)
            return true;
    }
    ::memset (basicInfoPtr, 0, sizeof (struct thread_basic_info));
    return false;
}


bool
MachThread::ThreadIDIsValid(uint64_t thread)
{
    return thread != 0;
}

bool
MachThread::MachPortNumberIsValid(thread_t thread)
{
    return thread != THREAD_NULL;
}

bool
MachThread::GetRegisterState(int flavor, bool force)
{
    return m_arch_ap->GetRegisterState(flavor, force) == KERN_SUCCESS;
}

bool
MachThread::SetRegisterState(int flavor)
{
    return m_arch_ap->SetRegisterState(flavor) == KERN_SUCCESS;
}

uint64_t
MachThread::GetPC(uint64_t failValue)
{
    // Get program counter
    return m_arch_ap->GetPC(failValue);
}

bool
MachThread::SetPC(uint64_t value)
{
    // Set program counter
    return m_arch_ap->SetPC(value);
}

uint64_t
MachThread::GetSP(uint64_t failValue)
{
    // Get stack pointer
    return m_arch_ap->GetSP(failValue);
}

nub_process_t
MachThread::ProcessID() const
{
    if (m_process)
        return m_process->ProcessID();
    return INVALID_NUB_PROCESS;
}

void
MachThread::Dump(uint32_t index)
{
    const char * thread_run_state = NULL;

    switch (m_basic_info.run_state)
    {
    case TH_STATE_RUNNING:          thread_run_state = "running"; break;    // 1 thread is running normally
    case TH_STATE_STOPPED:          thread_run_state = "stopped"; break;    // 2 thread is stopped
    case TH_STATE_WAITING:          thread_run_state = "waiting"; break;    // 3 thread is waiting normally
    case TH_STATE_UNINTERRUPTIBLE:  thread_run_state = "uninter"; break;    // 4 thread is in an uninterruptible wait
    case TH_STATE_HALTED:           thread_run_state = "halted "; break;     // 5 thread is halted at a
    default:                        thread_run_state = "???"; break;
    }

    DNBLogThreaded("[%3u] #%3u tid: 0x%8.8" PRIx64 ", pc: 0x%16.16" PRIx64 ", sp: 0x%16.16" PRIx64 ", user: %d.%6.6d, system: %d.%6.6d, cpu: %2d, policy: %2d, run_state: %2d (%s), flags: %2d, suspend_count: %2d (current %2d), sleep_time: %d",
        index,
        m_seq_id,
        m_unique_id,
        GetPC(INVALID_NUB_ADDRESS),
        GetSP(INVALID_NUB_ADDRESS),
        m_basic_info.user_time.seconds,      m_basic_info.user_time.microseconds,
        m_basic_info.system_time.seconds,    m_basic_info.system_time.microseconds,
        m_basic_info.cpu_usage,
        m_basic_info.policy,
        m_basic_info.run_state,
        thread_run_state,
        m_basic_info.flags,
        m_basic_info.suspend_count, m_suspend_count,
        m_basic_info.sleep_time);
    //DumpRegisterState(0);
}

void
MachThread::ThreadWillResume(const DNBThreadResumeAction *thread_action, bool others_stopped)
{
    if (thread_action->addr != INVALID_NUB_ADDRESS)
        SetPC (thread_action->addr);

    SetState (thread_action->state);
    switch (thread_action->state)
    {
    case eStateStopped:
    case eStateSuspended:
        assert (others_stopped == false);
        Suspend();
        break;

    case eStateRunning:
    case eStateStepping:
        Resume(others_stopped);
        break;
    default: 
        break;
    }
    m_arch_ap->ThreadWillResume();
    m_stop_exception.Clear();
}

DNBBreakpoint *
MachThread::CurrentBreakpoint()
{
    return m_process->Breakpoints().FindByAddress(GetPC());
}

bool
MachThread::ShouldStop(bool &step_more)
{
    // See if this thread is at a breakpoint?
    DNBBreakpoint *bp = CurrentBreakpoint();

    if (bp)
    {
        // This thread is sitting at a breakpoint, ask the breakpoint
        // if we should be stopping here.
        return true;
    }
    else
    {
        if (m_arch_ap->StepNotComplete())
        {
            step_more = true;
            return false;
        }
        // The thread state is used to let us know what the thread was
        // trying to do. MachThread::ThreadWillResume() will set the
        // thread state to various values depending if the thread was
        // the current thread and if it was to be single stepped, or
        // resumed.
        if (GetState() == eStateRunning)
        {
            // If our state is running, then we should continue as we are in
            // the process of stepping over a breakpoint.
            return false;
        }
        else
        {
            // Stop if we have any kind of valid exception for this
            // thread.
            if (GetStopException().IsValid())
                return true;
        }
    }
    return false;
}
bool
MachThread::IsStepping()
{
#if ENABLE_AUTO_STEPPING_OVER_BP
    // Return true if this thread is currently being stepped.
    // MachThread::ThreadWillResume currently determines this by looking if we
    // have been asked to single step, or if we are at a breakpoint instruction
    // and have been asked to resume. In the latter case we need to disable the
    // breakpoint we are at, single step, re-enable and continue.
    nub_state_t state = GetState();
    return ((state == eStateStepping) ||
            (state == eStateRunning && NUB_BREAK_ID_IS_VALID(CurrentBreakpoint())));
#else
    return GetState() == eStateStepping;
#endif
}


bool
MachThread::ThreadDidStop()
{
    // This thread has existed prior to resuming under debug nub control,
    // and has just been stopped. Do any cleanup that needs to be done
    // after running.

    // The thread state and breakpoint will still have the same values
    // as they had prior to resuming the thread, so it makes it easy to check
    // if we were trying to step a thread, or we tried to resume while being
    // at a breakpoint.

    // When this method gets called, the process state is still in the
    // state it was in while running so we can act accordingly.
    m_arch_ap->ThreadDidStop();


    // We may have suspended this thread so the primary thread could step
    // without worrying about race conditions, so lets restore our suspend
    // count.
    RestoreSuspendCountAfterStop();

    // Update the basic information for a thread
    MachThread::GetBasicInfo(m_mach_port_number, &m_basic_info);

#if ENABLE_AUTO_STEPPING_OVER_BP
    // See if we were at a breakpoint when we last resumed that we disabled,
    // re-enable it.
    nub_break_t breakID = CurrentBreakpoint();

    if (NUB_BREAK_ID_IS_VALID(breakID))
    {
        m_process->EnableBreakpoint(breakID);
        if (m_basic_info.suspend_count > 0)
        {
            SetState(eStateSuspended);
        }
        else
        {
            // If we last were at a breakpoint and we single stepped, our state
            // will be "running" to indicate we need to continue after stepping
            // over the breakpoint instruction. If we step over a breakpoint
            // instruction, we need to stop.
            if (GetState() == eStateRunning)
            {
                // Leave state set to running so we will continue automatically
                // from this breakpoint
            }
            else
            {
                SetState(eStateStopped);
            }
        }
    }
    else
    {
        if (m_basic_info.suspend_count > 0)
        {
            SetState(eStateSuspended);
        }
        else
        {
            SetState(eStateStopped);
        }
    }
#else
    if (m_basic_info.suspend_count > 0)
        SetState(eStateSuspended);
    else
        SetState(eStateStopped);
#endif
    return true;
}

bool
MachThread::NotifyException(MachException::Data& exc)
{
    // Allow the arch specific protocol to process (MachException::Data &)exc
    // first before possible reassignment of m_stop_exception with exc.
    // See also MachThread::GetStopException().
    bool handled = m_arch_ap->NotifyException(exc);

    if (m_stop_exception.IsValid())
    {
        // We may have more than one exception for a thread, but we need to
        // only remember the one that we will say is the reason we stopped.
        // We may have been single stepping and also gotten a signal exception,
        // so just remember the most pertinent one.
        if (m_stop_exception.IsBreakpoint())
            m_stop_exception = exc;
    }
    else
    {
        m_stop_exception = exc;
    }

    return handled;
}


nub_state_t
MachThread::GetState()
{
    // If any other threads access this we will need a mutex for it
    PTHREAD_MUTEX_LOCKER (locker, m_state_mutex);
    return m_state;
}

void
MachThread::SetState(nub_state_t state)
{
    PTHREAD_MUTEX_LOCKER (locker, m_state_mutex);
    m_state = state;
    DNBLogThreadedIf(LOG_THREAD, "MachThread::SetState ( %s ) for tid = 0x%8.8" PRIx64 "", DNBStateAsString(state), m_unique_id);
}

uint32_t
MachThread::GetNumRegistersInSet(int regSet) const
{
    if (regSet < m_num_reg_sets)
        return m_reg_sets[regSet].num_registers;
    return 0;
}

const char *
MachThread::GetRegisterSetName(int regSet) const
{
    if (regSet < m_num_reg_sets)
        return m_reg_sets[regSet].name;
    return NULL;
}

const DNBRegisterInfo *
MachThread::GetRegisterInfo(int regSet, int regIndex) const
{
    if (regSet < m_num_reg_sets)
        if (regIndex < m_reg_sets[regSet].num_registers)
            return &m_reg_sets[regSet].registers[regIndex];
    return NULL;
}
void
MachThread::DumpRegisterState(int regSet)
{
    if (regSet == REGISTER_SET_ALL)
    {
        for (regSet = 1; regSet < m_num_reg_sets; regSet++)
            DumpRegisterState(regSet);
    }
    else
    {
        if (m_arch_ap->RegisterSetStateIsValid(regSet))
        {
            const size_t numRegisters = GetNumRegistersInSet(regSet);
            size_t regIndex = 0;
            DNBRegisterValueClass reg;
            for (regIndex = 0; regIndex < numRegisters; ++regIndex)
            {
                if (m_arch_ap->GetRegisterValue(regSet, regIndex, &reg))
                {
                    reg.Dump(NULL, NULL);
                }
            }
        }
        else
        {
            DNBLog("%s: registers are not currently valid.", GetRegisterSetName(regSet));
        }
    }
}

const DNBRegisterSetInfo *
MachThread::GetRegisterSetInfo(nub_size_t *num_reg_sets ) const
{
    *num_reg_sets = m_num_reg_sets;
    return &m_reg_sets[0];
}

bool
MachThread::GetRegisterValue ( uint32_t set, uint32_t reg, DNBRegisterValue *value )
{
    return m_arch_ap->GetRegisterValue(set, reg, value);
}

bool
MachThread::SetRegisterValue ( uint32_t set, uint32_t reg, const DNBRegisterValue *value )
{
    return m_arch_ap->SetRegisterValue(set, reg, value);
}

nub_size_t
MachThread::GetRegisterContext (void *buf, nub_size_t buf_len)
{
    return m_arch_ap->GetRegisterContext(buf, buf_len);
}

nub_size_t
MachThread::SetRegisterContext (const void *buf, nub_size_t buf_len)
{
    return m_arch_ap->SetRegisterContext(buf, buf_len);
}

uint32_t
MachThread::EnableHardwareBreakpoint (const DNBBreakpoint *bp)
{
    if (bp != NULL && bp->IsBreakpoint())
        return m_arch_ap->EnableHardwareBreakpoint(bp->Address(), bp->ByteSize());
    return INVALID_NUB_HW_INDEX;
}

uint32_t
MachThread::EnableHardwareWatchpoint (const DNBBreakpoint *wp)
{
    if (wp != NULL && wp->IsWatchpoint())
        return m_arch_ap->EnableHardwareWatchpoint(wp->Address(), wp->ByteSize(), wp->WatchpointRead(), wp->WatchpointWrite());
    return INVALID_NUB_HW_INDEX;
}

// Provide a chance to update the global view of the hardware watchpoint state.
void
MachThread::HardwareWatchpointStateChanged ()
{
    m_arch_ap->HardwareWatchpointStateChanged();
}

bool
MachThread::RollbackTransForHWP()
{
    return m_arch_ap->RollbackTransForHWP();
}

bool
MachThread::FinishTransForHWP()
{
    return m_arch_ap->FinishTransForHWP();
}

bool
MachThread::DisableHardwareBreakpoint (const DNBBreakpoint *bp)
{
    if (bp != NULL && bp->IsHardware())
        return m_arch_ap->DisableHardwareBreakpoint(bp->GetHardwareIndex());
    return false;
}

bool
MachThread::DisableHardwareWatchpoint (const DNBBreakpoint *wp)
{
    if (wp != NULL && wp->IsHardware())
        return m_arch_ap->DisableHardwareWatchpoint(wp->GetHardwareIndex());
    return false;
}

uint32_t
MachThread::NumSupportedHardwareWatchpoints () const
{
    return m_arch_ap->NumSupportedHardwareWatchpoints();
}

bool
MachThread::GetIdentifierInfo ()
{
        // Don't try to get the thread info once and cache it for the life of the thread.  It changes over time, for instance
        // if the thread name changes, then the thread_handle also changes...  So you have to refetch it every time.
        mach_msg_type_number_t count = THREAD_IDENTIFIER_INFO_COUNT;
        kern_return_t kret = ::thread_info (m_mach_port_number, THREAD_IDENTIFIER_INFO, (thread_info_t) &m_ident_info, &count);
        return kret == KERN_SUCCESS;

    return false;
}


const char *
MachThread::GetName ()
{
    if (GetIdentifierInfo ())
    {
        int len = ::proc_pidinfo (m_process->ProcessID(), PROC_PIDTHREADINFO, m_ident_info.thread_handle, &m_proc_threadinfo, sizeof (m_proc_threadinfo));

        if (len && m_proc_threadinfo.pth_name[0])
            return m_proc_threadinfo.pth_name;
    }
    return NULL;
}


uint64_t 
MachThread::GetGloballyUniqueThreadIDForMachPortID (thread_t mach_port_id)
{
    kern_return_t kr;
    thread_identifier_info_data_t tident;
    mach_msg_type_number_t tident_count = THREAD_IDENTIFIER_INFO_COUNT;
    kr = thread_info (mach_port_id, THREAD_IDENTIFIER_INFO,
                      (thread_info_t) &tident, &tident_count);
    if (kr != KERN_SUCCESS)
    {
        return mach_port_id;
    }
    return tident.thread_id;
}

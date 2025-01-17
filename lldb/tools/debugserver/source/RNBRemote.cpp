//===-- RNBRemote.cpp -------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  Created by Greg Clayton on 12/12/07.
//
//===----------------------------------------------------------------------===//

#include "RNBRemote.h"

#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <mach/exception_types.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include "DNB.h"
#include "DNBLog.h"
#include "DNBThreadResumeActions.h"
#include "RNBContext.h"
#include "RNBServices.h"
#include "RNBSocket.h"
#include "Utility/StringExtractor.h"

#include <iomanip>
#include <sstream>
#include <TargetConditionals.h> // for endianness predefines

//----------------------------------------------------------------------
// std::iostream formatting macros
//----------------------------------------------------------------------
#define RAW_HEXBASE     std::setfill('0') << std::hex << std::right
#define HEXBASE         '0' << 'x' << RAW_HEXBASE
#define RAWHEX8(x)      RAW_HEXBASE << std::setw(2) << ((uint32_t)((uint8_t)x))
#define RAWHEX16        RAW_HEXBASE << std::setw(4)
#define RAWHEX32        RAW_HEXBASE << std::setw(8)
#define RAWHEX64        RAW_HEXBASE << std::setw(16)
#define HEX8(x)         HEXBASE << std::setw(2) << ((uint32_t)(x))
#define HEX16           HEXBASE << std::setw(4)
#define HEX32           HEXBASE << std::setw(8)
#define HEX64           HEXBASE << std::setw(16)
#define RAW_HEX(x)      RAW_HEXBASE << std::setw(sizeof(x)*2) << (x)
#define HEX(x)          HEXBASE << std::setw(sizeof(x)*2) << (x)
#define RAWHEX_SIZE(x, sz)  RAW_HEXBASE << std::setw((sz)) << (x)
#define HEX_SIZE(x, sz) HEXBASE << std::setw((sz)) << (x)
#define STRING_WIDTH(w) std::setfill(' ') << std::setw(w)
#define LEFT_STRING_WIDTH(s, w) std::left << std::setfill(' ') << std::setw(w) << (s) << std::right
#define DECIMAL         std::dec << std::setfill(' ')
#define DECIMAL_WIDTH(w) DECIMAL << std::setw(w)
#define FLOAT(n, d)     std::setfill(' ') << std::setw((n)+(d)+1) << std::setprecision(d) << std::showpoint << std::fixed
#define INDENT_WITH_SPACES(iword_idx)   std::setfill(' ') << std::setw((iword_idx)) << ""
#define INDENT_WITH_TABS(iword_idx)     std::setfill('\t') << std::setw((iword_idx)) << ""
// Class to handle communications via gdb remote protocol.

extern void ASLLogCallback(void *baton, uint32_t flags, const char *format, va_list args);

RNBRemote::RNBRemote () :
    m_ctx (),
    m_comm (),
    m_continue_thread(-1),
    m_thread(-1),
    m_mutex(),
    m_packets_recvd(0),
    m_packets(),
    m_rx_packets(),
    m_rx_partial_data(),
    m_rx_pthread(0),
    m_max_payload_size(DEFAULT_GDB_REMOTE_PROTOCOL_BUFSIZE - 4),
    m_extended_mode(false),
    m_noack_mode(false),
    m_use_native_regs (false),
    m_thread_suffix_supported (false),
    m_list_threads_in_stop_reply (false)
{
    DNBLogThreadedIf (LOG_RNB_REMOTE, "%s", __PRETTY_FUNCTION__);
    CreatePacketTable ();
}


RNBRemote::~RNBRemote()
{
    DNBLogThreadedIf (LOG_RNB_REMOTE, "%s", __PRETTY_FUNCTION__);
    StopReadRemoteDataThread();
}

void
RNBRemote::CreatePacketTable  ()
{
    // Step required to add new packets:
    // 1 - Add new enumeration to RNBRemote::PacketEnum
    // 2 - Create a the RNBRemote::HandlePacket_ function if a new function is needed
    // 3 - Register the Packet definition with any needed callbacks in this function
    //          - If no response is needed for a command, then use NULL for the normal callback
    //          - If the packet is not supported while the target is running, use NULL for the async callback
    // 4 - If the packet is a standard packet (starts with a '$' character
    //      followed by the payload and then '#' and checksum, then you are done
    //      else go on to step 5
    // 5 - if the packet is a fixed length packet:
    //      - modify the switch statement for the first character in the payload
    //        in RNBRemote::CommDataReceived so it doesn't reject the new packet
    //        type as invalid
    //      - modify the switch statement for the first character in the payload
    //        in RNBRemote::GetPacketPayload and make sure the payload of the packet
    //        is returned correctly

    std::vector <Packet> &t = m_packets;
    t.push_back (Packet (ack,                           NULL,                                   NULL, "+", "ACK"));
    t.push_back (Packet (nack,                          NULL,                                   NULL, "-", "!ACK"));
    t.push_back (Packet (read_memory,                   &RNBRemote::HandlePacket_m,             NULL, "m", "Read memory"));
    t.push_back (Packet (read_register,                 &RNBRemote::HandlePacket_p,             NULL, "p", "Read one register"));
    t.push_back (Packet (read_general_regs,             &RNBRemote::HandlePacket_g,             NULL, "g", "Read registers"));
    t.push_back (Packet (write_memory,                  &RNBRemote::HandlePacket_M,             NULL, "M", "Write memory"));
    t.push_back (Packet (write_register,                &RNBRemote::HandlePacket_P,             NULL, "P", "Write one register"));
    t.push_back (Packet (write_general_regs,            &RNBRemote::HandlePacket_G,             NULL, "G", "Write registers"));
    t.push_back (Packet (insert_mem_bp,                 &RNBRemote::HandlePacket_z,             NULL, "Z0", "Insert memory breakpoint"));
    t.push_back (Packet (remove_mem_bp,                 &RNBRemote::HandlePacket_z,             NULL, "z0", "Remove memory breakpoint"));
    t.push_back (Packet (single_step,                   &RNBRemote::HandlePacket_s,             NULL, "s", "Single step"));
    t.push_back (Packet (cont,                          &RNBRemote::HandlePacket_c,             NULL, "c", "continue"));
    t.push_back (Packet (single_step_with_sig,          &RNBRemote::HandlePacket_S,             NULL, "S", "Single step with signal"));
    t.push_back (Packet (set_thread,                    &RNBRemote::HandlePacket_H,             NULL, "H", "Set thread"));
    t.push_back (Packet (halt,                          &RNBRemote::HandlePacket_last_signal,   &RNBRemote::HandlePacket_stop_process, "\x03", "^C"));
//  t.push_back (Packet (use_extended_mode,             &RNBRemote::HandlePacket_UNIMPLEMENTED, NULL, "!", "Use extended mode"));
    t.push_back (Packet (why_halted,                    &RNBRemote::HandlePacket_last_signal,   NULL, "?", "Why did target halt"));
    t.push_back (Packet (set_argv,                      &RNBRemote::HandlePacket_A,             NULL, "A", "Set argv"));
//  t.push_back (Packet (set_bp,                        &RNBRemote::HandlePacket_UNIMPLEMENTED, NULL, "B", "Set/clear breakpoint"));
    t.push_back (Packet (continue_with_sig,             &RNBRemote::HandlePacket_C,             NULL, "C", "Continue with signal"));
    t.push_back (Packet (detach,                        &RNBRemote::HandlePacket_D,             NULL, "D", "Detach gdb from remote system"));
//  t.push_back (Packet (step_inferior_one_cycle,       &RNBRemote::HandlePacket_UNIMPLEMENTED, NULL, "i", "Step inferior by one clock cycle"));
//  t.push_back (Packet (signal_and_step_inf_one_cycle, &RNBRemote::HandlePacket_UNIMPLEMENTED, NULL, "I", "Signal inferior, then step one clock cyle"));
    t.push_back (Packet (kill,                          &RNBRemote::HandlePacket_k,             NULL, "k", "Kill"));
//  t.push_back (Packet (restart,                       &RNBRemote::HandlePacket_UNIMPLEMENTED, NULL, "R", "Restart inferior"));
//  t.push_back (Packet (search_mem_backwards,          &RNBRemote::HandlePacket_UNIMPLEMENTED, NULL, "t", "Search memory backwards"));
    t.push_back (Packet (thread_alive_p,                &RNBRemote::HandlePacket_T,             NULL, "T", "Is thread alive"));
    t.push_back (Packet (vattach,                       &RNBRemote::HandlePacket_v,             NULL, "vAttach", "Attach to a new process"));
    t.push_back (Packet (vattachwait,                   &RNBRemote::HandlePacket_v,             NULL, "vAttachWait", "Wait for a process to start up then attach to it"));
    t.push_back (Packet (vattachorwait,                 &RNBRemote::HandlePacket_v,             NULL, "vAttachOrWait", "Attach to the process or if it doesn't exist, wait for the process to start up then attach to it"));
    t.push_back (Packet (vattachname,                   &RNBRemote::HandlePacket_v,             NULL, "vAttachName", "Attach to an existing process by name"));
    t.push_back (Packet (vcont_list_actions,            &RNBRemote::HandlePacket_v,             NULL, "vCont;", "Verbose resume with thread actions"));
    t.push_back (Packet (vcont_list_actions,            &RNBRemote::HandlePacket_v,             NULL, "vCont?", "List valid continue-with-thread-actions actions"));
    // The X packet doesn't currently work. If/when it does, remove the line above and uncomment out the line below
//  t.push_back (Packet (write_data_to_memory,          &RNBRemote::HandlePacket_X,             NULL, "X", "Write data to memory"));
//  t.push_back (Packet (insert_hardware_bp,            &RNBRemote::HandlePacket_UNIMPLEMENTED, NULL, "Z1", "Insert hardware breakpoint"));
//  t.push_back (Packet (remove_hardware_bp,            &RNBRemote::HandlePacket_UNIMPLEMENTED, NULL, "z1", "Remove hardware breakpoint"));
    t.push_back (Packet (insert_write_watch_bp,         &RNBRemote::HandlePacket_z,             NULL, "Z2", "Insert write watchpoint"));
    t.push_back (Packet (remove_write_watch_bp,         &RNBRemote::HandlePacket_z,             NULL, "z2", "Remove write watchpoint"));
    t.push_back (Packet (insert_read_watch_bp,          &RNBRemote::HandlePacket_z,             NULL, "Z3", "Insert read watchpoint"));
    t.push_back (Packet (remove_read_watch_bp,          &RNBRemote::HandlePacket_z,             NULL, "z3", "Remove read watchpoint"));
    t.push_back (Packet (insert_access_watch_bp,        &RNBRemote::HandlePacket_z,             NULL, "Z4", "Insert access watchpoint"));
    t.push_back (Packet (remove_access_watch_bp,        &RNBRemote::HandlePacket_z,             NULL, "z4", "Remove access watchpoint"));
    t.push_back (Packet (query_monitor,                 &RNBRemote::HandlePacket_qRcmd,          NULL, "qRcmd", "Monitor command"));
    t.push_back (Packet (query_current_thread_id,       &RNBRemote::HandlePacket_qC,            NULL, "qC", "Query current thread ID"));
    t.push_back (Packet (query_get_pid,                 &RNBRemote::HandlePacket_qGetPid,       NULL, "qGetPid", "Query process id"));
    t.push_back (Packet (query_thread_ids_first,        &RNBRemote::HandlePacket_qThreadInfo,   NULL, "qfThreadInfo", "Get list of active threads (first req)"));
    t.push_back (Packet (query_thread_ids_subsequent,   &RNBRemote::HandlePacket_qThreadInfo,   NULL, "qsThreadInfo", "Get list of active threads (subsequent req)"));
    // APPLE LOCAL: qThreadStopInfo
    // syntax: qThreadStopInfoTTTT
    //  TTTT is hex thread ID
    t.push_back (Packet (query_thread_stop_info,        &RNBRemote::HandlePacket_qThreadStopInfo,   NULL, "qThreadStopInfo", "Get detailed info on why the specified thread stopped"));
    t.push_back (Packet (query_thread_extra_info,       &RNBRemote::HandlePacket_qThreadExtraInfo,NULL, "qThreadExtraInfo", "Get printable status of a thread"));
//  t.push_back (Packet (query_image_offsets,           &RNBRemote::HandlePacket_UNIMPLEMENTED, NULL, "qOffsets", "Report offset of loaded program"));
    t.push_back (Packet (query_launch_success,          &RNBRemote::HandlePacket_qLaunchSuccess,NULL, "qLaunchSuccess", "Report the success or failure of the launch attempt"));
    t.push_back (Packet (query_register_info,           &RNBRemote::HandlePacket_qRegisterInfo, NULL, "qRegisterInfo", "Dynamically discover remote register context information."));
    t.push_back (Packet (query_shlib_notify_info_addr,  &RNBRemote::HandlePacket_qShlibInfoAddr,NULL, "qShlibInfoAddr", "Returns the address that contains info needed for getting shared library notifications"));
    t.push_back (Packet (query_step_packet_supported,   &RNBRemote::HandlePacket_qStepPacketSupported,NULL, "qStepPacketSupported", "Replys with OK if the 's' packet is supported."));
    t.push_back (Packet (query_vattachorwait_supported, &RNBRemote::HandlePacket_qVAttachOrWaitSupported,NULL, "qVAttachOrWaitSupported", "Replys with OK if the 'vAttachOrWait' packet is supported."));
    t.push_back (Packet (query_sync_thread_state_supported, &RNBRemote::HandlePacket_qSyncThreadStateSupported,NULL, "qSyncThreadStateSupported", "Replys with OK if the 'QSyncThreadState:' packet is supported."));
    t.push_back (Packet (query_host_info,               &RNBRemote::HandlePacket_qHostInfo,     NULL, "qHostInfo", "Replies with multiple 'key:value;' tuples appended to each other."));
    t.push_back (Packet (query_process_info,            &RNBRemote::HandlePacket_qProcessInfo,     NULL, "qProcessInfo", "Replies with multiple 'key:value;' tuples appended to each other."));
//  t.push_back (Packet (query_symbol_lookup,           &RNBRemote::HandlePacket_UNIMPLEMENTED, NULL, "qSymbol", "Notify that host debugger is ready to do symbol lookups"));
    t.push_back (Packet (start_noack_mode,              &RNBRemote::HandlePacket_QStartNoAckMode        , NULL, "QStartNoAckMode", "Request that " DEBUGSERVER_PROGRAM_NAME " stop acking remote protocol packets"));
    t.push_back (Packet (prefix_reg_packets_with_tid,   &RNBRemote::HandlePacket_QThreadSuffixSupported , NULL, "QThreadSuffixSupported", "Check if thread specifc packets (register packets 'g', 'G', 'p', and 'P') support having the thread ID appended to the end of the command"));
    t.push_back (Packet (set_logging_mode,              &RNBRemote::HandlePacket_QSetLogging            , NULL, "QSetLogging:", "Check if register packets ('g', 'G', 'p', and 'P' support having the thread ID prefix"));
    t.push_back (Packet (set_max_packet_size,           &RNBRemote::HandlePacket_QSetMaxPacketSize      , NULL, "QSetMaxPacketSize:", "Tell " DEBUGSERVER_PROGRAM_NAME " the max sized packet gdb can handle"));
    t.push_back (Packet (set_max_payload_size,          &RNBRemote::HandlePacket_QSetMaxPayloadSize     , NULL, "QSetMaxPayloadSize:", "Tell " DEBUGSERVER_PROGRAM_NAME " the max sized payload gdb can handle"));
    t.push_back (Packet (set_environment_variable,      &RNBRemote::HandlePacket_QEnvironment           , NULL, "QEnvironment:", "Add an environment variable to the inferior's environment"));
    t.push_back (Packet (set_environment_variable_hex,  &RNBRemote::HandlePacket_QEnvironmentHexEncoded , NULL, "QEnvironmentHexEncoded:", "Add an environment variable to the inferior's environment"));
    t.push_back (Packet (set_launch_arch,               &RNBRemote::HandlePacket_QLaunchArch            , NULL, "QLaunchArch:", "Set the architecture to use when launching a process for hosts that can run multiple architecture slices from universal files."));
    t.push_back (Packet (set_disable_aslr,              &RNBRemote::HandlePacket_QSetDisableASLR        , NULL, "QSetDisableASLR:", "Set wether to disable ASLR when launching the process with the set argv ('A') packet"));
    t.push_back (Packet (set_stdin,                     &RNBRemote::HandlePacket_QSetSTDIO              , NULL, "QSetSTDIN:", "Set the standard input for a process to be launched with the 'A' packet"));
    t.push_back (Packet (set_stdout,                    &RNBRemote::HandlePacket_QSetSTDIO              , NULL, "QSetSTDOUT:", "Set the standard output for a process to be launched with the 'A' packet"));
    t.push_back (Packet (set_stderr,                    &RNBRemote::HandlePacket_QSetSTDIO              , NULL, "QSetSTDERR:", "Set the standard error for a process to be launched with the 'A' packet"));
    t.push_back (Packet (set_working_dir,               &RNBRemote::HandlePacket_QSetWorkingDir         , NULL, "QSetWorkingDir:", "Set the working directory for a process to be launched with the 'A' packet"));
    t.push_back (Packet (set_list_threads_in_stop_reply,&RNBRemote::HandlePacket_QListThreadsInStopReply , NULL, "QListThreadsInStopReply", "Set if the 'threads' key should be added to the stop reply packets with a list of all thread IDs."));
    t.push_back (Packet (sync_thread_state,             &RNBRemote::HandlePacket_QSyncThreadState , NULL, "QSyncThreadState:", "Do whatever is necessary to make sure 'thread' is in a safe state to call functions on."));
//  t.push_back (Packet (pass_signals_to_inferior,      &RNBRemote::HandlePacket_UNIMPLEMENTED, NULL, "QPassSignals:", "Specify which signals are passed to the inferior"));
    t.push_back (Packet (allocate_memory,               &RNBRemote::HandlePacket_AllocateMemory, NULL, "_M", "Allocate memory in the inferior process."));
    t.push_back (Packet (deallocate_memory,             &RNBRemote::HandlePacket_DeallocateMemory, NULL, "_m", "Deallocate memory in the inferior process."));
    t.push_back (Packet (memory_region_info,            &RNBRemote::HandlePacket_MemoryRegionInfo, NULL, "qMemoryRegionInfo", "Return size and attributes of a memory region that contains the given address"));
    t.push_back (Packet (get_profile_data,              &RNBRemote::HandlePacket_GetProfileData, NULL, "qGetProfileData", "Return profiling data of the current target."));
    t.push_back (Packet (set_enable_profiling,          &RNBRemote::HandlePacket_SetEnableAsyncProfiling, NULL, "QSetEnableAsyncProfiling", "Enable or disable the profiling of current target."));
    t.push_back (Packet (watchpoint_support_info,       &RNBRemote::HandlePacket_WatchpointSupportInfo, NULL, "qWatchpointSupportInfo", "Return the number of supported hardware watchpoints"));

}


void
RNBRemote::FlushSTDIO ()
{
    if (m_ctx.HasValidProcessID())
    {
        nub_process_t pid = m_ctx.ProcessID();
        char buf[256];
        nub_size_t count;
        do
        {
            count = DNBProcessGetAvailableSTDOUT(pid, buf, sizeof(buf));
            if (count > 0)
            {
                SendSTDOUTPacket (buf, count);
            }
        } while (count > 0);

        do
        {
            count = DNBProcessGetAvailableSTDERR(pid, buf, sizeof(buf));
            if (count > 0)
            {
                SendSTDERRPacket (buf, count);
            }
        } while (count > 0);
    }
}

void
RNBRemote::SendAsyncProfileData ()
{
    if (m_ctx.HasValidProcessID())
    {
        nub_process_t pid = m_ctx.ProcessID();
        char buf[1024];
        nub_size_t count;
        do
        {
            count = DNBProcessGetAvailableProfileData(pid, buf, sizeof(buf));
            if (count > 0)
            {
                SendAsyncProfileDataPacket (buf, count);
            }
        } while (count > 0);
    }
}

rnb_err_t
RNBRemote::SendHexEncodedBytePacket (const char *header, const void *buf, size_t buf_len, const char *footer)
{
    std::ostringstream packet_sstrm;
    // Append the header cstr if there was one
    if (header && header[0])
        packet_sstrm << header;
    nub_size_t i;
    const uint8_t *ubuf8 = (const uint8_t *)buf;
    for (i=0; i<buf_len; i++)
    {
        packet_sstrm << RAWHEX8(ubuf8[i]);
    }
    // Append the footer cstr if there was one
    if (footer && footer[0])
        packet_sstrm << footer;

    return SendPacket(packet_sstrm.str());
}

rnb_err_t
RNBRemote::SendSTDOUTPacket (char *buf, nub_size_t buf_size)
{
    if (buf_size == 0)
        return rnb_success;
    return SendHexEncodedBytePacket("O", buf, buf_size, NULL);
}

rnb_err_t
RNBRemote::SendSTDERRPacket (char *buf, nub_size_t buf_size)
{
    if (buf_size == 0)
        return rnb_success;
    return SendHexEncodedBytePacket("O", buf, buf_size, NULL);
}

// This makes use of asynchronous bit 'A' in the gdb remote protocol.
rnb_err_t
RNBRemote::SendAsyncProfileDataPacket (char *buf, nub_size_t buf_size)
{
    if (buf_size == 0)
        return rnb_success;
    
    std::string packet("A");
    packet.append(buf, buf_size);
    return SendPacket(packet);
}

rnb_err_t
RNBRemote::SendPacket (const std::string &s)
{
    DNBLogThreadedIf (LOG_RNB_MAX, "%8d RNBRemote::%s (%s) called", (uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__, s.c_str());
    std::string sendpacket = "$" + s + "#";
    int cksum = 0;
    char hexbuf[5];

    if (m_noack_mode)
    {
        sendpacket += "00";
    }
    else
    {
        for (int i = 0; i != s.size(); ++i)
            cksum += s[i];
        snprintf (hexbuf, sizeof hexbuf, "%02x", cksum & 0xff);
        sendpacket += hexbuf;
    }

    rnb_err_t err = m_comm.Write (sendpacket.c_str(), sendpacket.size());
    if (err != rnb_success)
        return err;

    if (m_noack_mode)
        return rnb_success;

    std::string reply;
    RNBRemote::Packet packet;
    err = GetPacket (reply, packet, true);

    if (err != rnb_success)
    {
        DNBLogThreadedIf (LOG_RNB_REMOTE, "%8d RNBRemote::%s (%s) got error trying to get reply...", (uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__, sendpacket.c_str());
        return err;
    }

    DNBLogThreadedIf (LOG_RNB_MAX, "%8d RNBRemote::%s (%s) got reply: '%s'", (uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__, sendpacket.c_str(), reply.c_str());

    if (packet.type == ack)
        return rnb_success;

    // Should we try to resend the packet at this layer?
    //  if (packet.command == nack)
    return rnb_err;
}

/* Get a packet via gdb remote protocol.
 Strip off the prefix/suffix, verify the checksum to make sure
 a valid packet was received, send an ACK if they match.  */

rnb_err_t
RNBRemote::GetPacketPayload (std::string &return_packet)
{
    //DNBLogThreadedIf (LOG_RNB_MAX, "%8u RNBRemote::%s called", (uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__);

    PThreadMutex::Locker locker(m_mutex);
    if (m_rx_packets.empty())
    {
        // Only reset the remote command available event if we have no more packets
        m_ctx.Events().ResetEvents ( RNBContext::event_read_packet_available );
        //DNBLogThreadedIf (LOG_RNB_MAX, "%8u RNBRemote::%s error: no packets available...", (uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__);
        return rnb_err;
    }

    //DNBLogThreadedIf (LOG_RNB_MAX, "%8u RNBRemote::%s has %u queued packets", (uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__, m_rx_packets.size());
    return_packet.swap(m_rx_packets.front());
    m_rx_packets.pop_front();
    locker.Reset(); // Release our lock on the mutex

    if (m_rx_packets.empty())
    {
        // Reset the remote command available event if we have no more packets
        m_ctx.Events().ResetEvents ( RNBContext::event_read_packet_available );
    }

    //DNBLogThreadedIf (LOG_RNB_MEDIUM, "%8u RNBRemote::%s: '%s'", (uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__, return_packet.c_str());

    switch (return_packet[0])
    {
        case '+':
        case '-':
        case '\x03':
            break;

        case '$':
        {
            int packet_checksum = 0;
            if (!m_noack_mode)
            {
                for (int i = return_packet.size() - 2; i < return_packet.size(); ++i)
                {
                    char checksum_char = tolower (return_packet[i]);
                    if (!isxdigit (checksum_char))
                    {
                        m_comm.Write ("-", 1);
                        DNBLogThreadedIf (LOG_RNB_REMOTE, "%8u RNBRemote::%s error: packet with invalid checksum characters: %s", (uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__, return_packet.c_str());
                        return rnb_err;
                    }
                }
                packet_checksum = strtol (&return_packet[return_packet.size() - 2], NULL, 16);
            }

            return_packet.erase(0,1);           // Strip the leading '$'
            return_packet.erase(return_packet.size() - 3);// Strip the #XX checksum

            if (!m_noack_mode)
            {
                // Compute the checksum
                int computed_checksum = 0;
                for (std::string::iterator it = return_packet.begin ();
                     it != return_packet.end ();
                     ++it)
                {
                    computed_checksum += *it;
                }

                if (packet_checksum == (computed_checksum & 0xff))
                {
                    //DNBLogThreadedIf (LOG_RNB_MEDIUM, "%8u RNBRemote::%s sending ACK for '%s'", (uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__, return_packet.c_str());
                    m_comm.Write ("+", 1);
                }
                else
                {
                    DNBLogThreadedIf (LOG_RNB_MEDIUM, "%8u RNBRemote::%s sending ACK for '%s' (error: packet checksum mismatch  (0x%2.2x != 0x%2.2x))",
                                      (uint32_t)m_comm.Timer().ElapsedMicroSeconds(true),
                                      __FUNCTION__,
                                      return_packet.c_str(),
                                      packet_checksum,
                                      computed_checksum);
                    m_comm.Write ("-", 1);
                    return rnb_err;
                }
            }
        }
        break;

        default:
            DNBLogThreadedIf (LOG_RNB_REMOTE, "%8u RNBRemote::%s tossing unexpected packet???? %s", (uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__, return_packet.c_str());
            if (!m_noack_mode)
                m_comm.Write ("-", 1);
            return rnb_err;
    }

    return rnb_success;
}

rnb_err_t
RNBRemote::HandlePacket_UNIMPLEMENTED (const char* p)
{
    DNBLogThreadedIf (LOG_RNB_MAX, "%8u RNBRemote::%s(\"%s\")", (uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__, p ? p : "NULL");
    return SendPacket ("");
}

rnb_err_t
RNBRemote::HandlePacket_ILLFORMED (const char *file, int line, const char *p, const char *description)
{
    DNBLogThreadedIf (LOG_RNB_PACKETS, "%8u %s:%i ILLFORMED: '%s' (%s)", (uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), file, line, __FUNCTION__, p);
    return SendPacket ("E03");
}

rnb_err_t
RNBRemote::GetPacket (std::string &packet_payload, RNBRemote::Packet& packet_info, bool wait)
{
    std::string payload;
    rnb_err_t err = GetPacketPayload (payload);
    if (err != rnb_success)
    {
        PThreadEvent& events = m_ctx.Events();
        nub_event_t set_events = events.GetEventBits();
        // TODO: add timeout version of GetPacket?? We would then need to pass
        // that timeout value along to DNBProcessTimedWaitForEvent.
        if (!wait || ((set_events & RNBContext::event_read_thread_running) == 0))
            return err;

        const nub_event_t events_to_wait_for = RNBContext::event_read_packet_available | RNBContext::event_read_thread_exiting;

        while ((set_events = events.WaitForSetEvents(events_to_wait_for)) != 0)
        {
            if (set_events & RNBContext::event_read_packet_available)
            {
                // Try the queue again now that we got an event
                err = GetPacketPayload (payload);
                if (err == rnb_success)
                    break;
            }

            if (set_events & RNBContext::event_read_thread_exiting)
                err = rnb_not_connected;

            if (err == rnb_not_connected)
                return err;

        } while (err == rnb_err);

        if (set_events == 0)
            err = rnb_not_connected;
    }

    if (err == rnb_success)
    {
        Packet::iterator it;
        for (it = m_packets.begin (); it != m_packets.end (); ++it)
        {
            if (payload.compare (0, it->abbrev.size(), it->abbrev) == 0)
                break;
        }

        // A packet we don't have an entry for. This can happen when we
        // get a packet that we don't know about or support. We just reply
        // accordingly and go on.
        if (it == m_packets.end ())
        {
            DNBLogThreadedIf (LOG_RNB_PACKETS, "unimplemented packet: '%s'", payload.c_str());
            HandlePacket_UNIMPLEMENTED(payload.c_str());
            return rnb_err;
        }
        else
        {
            packet_info = *it;
            packet_payload = payload;
        }
    }
    return err;
}

rnb_err_t
RNBRemote::HandleAsyncPacket(PacketEnum *type)
{
    DNBLogThreadedIf (LOG_RNB_REMOTE, "%8u RNBRemote::%s", (uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__);
    static DNBTimer g_packetTimer(true);
    rnb_err_t err = rnb_err;
    std::string packet_data;
    RNBRemote::Packet packet_info;
    err = GetPacket (packet_data, packet_info, false);

    if (err == rnb_success)
    {
        if (!packet_data.empty() && isprint(packet_data[0]))
            DNBLogThreadedIf (LOG_RNB_REMOTE | LOG_RNB_PACKETS, "HandleAsyncPacket (\"%s\");", packet_data.c_str());
        else
            DNBLogThreadedIf (LOG_RNB_REMOTE | LOG_RNB_PACKETS, "HandleAsyncPacket (%s);", packet_info.printable_name.c_str());

        HandlePacketCallback packet_callback = packet_info.async;
        if (packet_callback != NULL)
        {
            if (type != NULL)
                *type = packet_info.type;
            return (this->*packet_callback)(packet_data.c_str());
        }
    }

    return err;
}

rnb_err_t
RNBRemote::HandleReceivedPacket(PacketEnum *type)
{
    static DNBTimer g_packetTimer(true);

    //  DNBLogThreadedIf (LOG_RNB_REMOTE, "%8u RNBRemote::%s", (uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__);
    rnb_err_t err = rnb_err;
    std::string packet_data;
    RNBRemote::Packet packet_info;
    err = GetPacket (packet_data, packet_info, false);

    if (err == rnb_success)
    {
        DNBLogThreadedIf (LOG_RNB_REMOTE, "HandleReceivedPacket (\"%s\");", packet_data.c_str());
        HandlePacketCallback packet_callback = packet_info.normal;
        if (packet_callback != NULL)
        {
            if (type != NULL)
                *type = packet_info.type;
            return (this->*packet_callback)(packet_data.c_str());
        }
        else
        {
            // Do not fall through to end of this function, if we have valid
            // packet_info and it has a NULL callback, then we need to respect
            // that it may not want any response or anything to be done.
            return err;
        }
    }
    return rnb_err;
}

void
RNBRemote::CommDataReceived(const std::string& new_data)
{
    //  DNBLogThreadedIf (LOG_RNB_REMOTE, "%8d RNBRemote::%s called", (uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__);
    {
        // Put the packet data into the buffer in a thread safe fashion
        PThreadMutex::Locker locker(m_mutex);

        std::string data;
        // See if we have any left over data from a previous call to this
        // function?
        if (!m_rx_partial_data.empty())
        {
            // We do, so lets start with that data
            data.swap(m_rx_partial_data);
        }
        // Append the new incoming data
        data += new_data;

        // Parse up the packets into gdb remote packets
        uint32_t idx = 0;
        const size_t data_size = data.size();

        while (idx < data_size)
        {
            // end_idx must be one past the last valid packet byte. Start
            // it off with an invalid value that is the same as the current
            // index.
            size_t end_idx = idx;

            switch (data[idx])
            {
                case '+':       // Look for ack
                case '-':       // Look for cancel
                case '\x03':    // ^C to halt target
                    end_idx = idx + 1;  // The command is one byte long...
                    break;

                case '$':
                    // Look for a standard gdb packet?
                    end_idx = data.find('#',  idx + 1);
                    if (end_idx == std::string::npos || end_idx + 3 > data_size)
                    {
                        end_idx = std::string::npos;
                    }
                    else
                    {
                        // Add two for the checksum bytes and 1 to point to the
                        // byte just past the end of this packet
                        end_idx += 3;
                    }
                    break;

                default:
                    break;
            }

            if (end_idx == std::string::npos)
            {
                // Not all data may be here for the packet yet, save it for
                // next time through this function.
                m_rx_partial_data += data.substr(idx);
                //DNBLogThreadedIf (LOG_RNB_MAX, "%8d RNBRemote::%s saving data for later[%u, npos): '%s'",(uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__, idx, m_rx_partial_data.c_str());
                idx = end_idx;
            }
            else
                if (idx < end_idx)
                {
                    m_packets_recvd++;
                    // Hack to get rid of initial '+' ACK???
                    if (m_packets_recvd == 1 && (end_idx == idx + 1) && data[idx] == '+')
                    {
                        //DNBLogThreadedIf (LOG_RNB_REMOTE, "%8d RNBRemote::%s throwing first ACK away....[%u, npos): '+'",(uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__, idx);
                    }
                    else
                    {
                        // We have a valid packet...
                        m_rx_packets.push_back(data.substr(idx, end_idx - idx));
                        DNBLogThreadedIf (LOG_RNB_PACKETS, "getpkt: %s", m_rx_packets.back().c_str());
                    }
                    idx = end_idx;
                }
                else
                {
                    DNBLogThreadedIf (LOG_RNB_MAX, "%8d RNBRemote::%s tossing junk byte at %c",(uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__, data[idx]);
                    idx = idx + 1;
                }
        }
    }

    if (!m_rx_packets.empty())
    {
        // Let the main thread know we have received a packet

        //DNBLogThreadedIf (LOG_RNB_EVENTS, "%8d RNBRemote::%s   called events.SetEvent(RNBContext::event_read_packet_available)", (uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__);
        PThreadEvent& events = m_ctx.Events();
        events.SetEvents (RNBContext::event_read_packet_available);
    }
}

rnb_err_t
RNBRemote::GetCommData ()
{
    //  DNBLogThreadedIf (LOG_RNB_REMOTE, "%8d RNBRemote::%s called", (uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__);
    std::string comm_data;
    rnb_err_t err = m_comm.Read (comm_data);
    if (err == rnb_success)
    {
        if (!comm_data.empty())
            CommDataReceived (comm_data);
    }
    return err;
}

void
RNBRemote::StartReadRemoteDataThread()
{
    DNBLogThreadedIf (LOG_RNB_REMOTE, "%8u RNBRemote::%s called", (uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__);
    PThreadEvent& events = m_ctx.Events();
    if ((events.GetEventBits() & RNBContext::event_read_thread_running) == 0)
    {
        events.ResetEvents (RNBContext::event_read_thread_exiting);
        int err = ::pthread_create (&m_rx_pthread, NULL, ThreadFunctionReadRemoteData, this);
        if (err == 0)
        {
            // Our thread was successfully kicked off, wait for it to
            // set the started event so we can safely continue
            events.WaitForSetEvents (RNBContext::event_read_thread_running);
        }
        else
        {
            events.ResetEvents (RNBContext::event_read_thread_running);
            events.SetEvents (RNBContext::event_read_thread_exiting);
        }
    }
}

void
RNBRemote::StopReadRemoteDataThread()
{
    DNBLogThreadedIf (LOG_RNB_REMOTE, "%8u RNBRemote::%s called", (uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__);
    PThreadEvent& events = m_ctx.Events();
    if ((events.GetEventBits() & RNBContext::event_read_thread_running) == RNBContext::event_read_thread_running)
    {
        m_comm.Disconnect(true);
        struct timespec timeout_abstime;
        DNBTimer::OffsetTimeOfDay(&timeout_abstime, 2, 0);

        // Wait for 2 seconds for the remote data thread to exit
        if (events.WaitForSetEvents(RNBContext::event_read_thread_exiting, &timeout_abstime) == 0)
        {
            // Kill the remote data thread???
        }
    }
}


void*
RNBRemote::ThreadFunctionReadRemoteData(void *arg)
{
    // Keep a shared pointer reference so this doesn't go away on us before the thread is killed.
    DNBLogThreadedIf(LOG_RNB_REMOTE, "RNBRemote::%s (%p): thread starting...", __FUNCTION__, arg);
    RNBRemoteSP remoteSP(g_remoteSP);
    if (remoteSP.get() != NULL)
    {
        RNBRemote* remote = remoteSP.get();
        PThreadEvent& events = remote->Context().Events();
        events.SetEvents (RNBContext::event_read_thread_running);
        // START: main receive remote command thread loop
        bool done = false;
        while (!done)
        {
            rnb_err_t err = remote->GetCommData();

            switch (err)
            {
                case rnb_success:
                    break;

                default:
                case rnb_err:
                    DNBLogThreadedIf (LOG_RNB_REMOTE, "RNBSocket::GetCommData returned error %u", err);
                    done = true;
                    break;

                case rnb_not_connected:
                    DNBLogThreadedIf (LOG_RNB_REMOTE, "RNBSocket::GetCommData returned not connected...");
                    done = true;
                    break;
            }
        }
        // START: main receive remote command thread loop
        events.ResetEvents (RNBContext::event_read_thread_running);
        events.SetEvents (RNBContext::event_read_thread_exiting);
    }
    DNBLogThreadedIf(LOG_RNB_REMOTE, "RNBRemote::%s (%p): thread exiting...", __FUNCTION__, arg);
    return NULL;
}



/* Read the bytes in STR which are GDB Remote Protocol binary encoded bytes
 (8-bit bytes).
 This encoding uses 0x7d ('}') as an escape character for 0x7d ('}'),
 0x23 ('#'), and 0x24 ('$').
 LEN is the number of bytes to be processed.  If a character is escaped,
 it is 2 characters for LEN.  A LEN of -1 means encode-until-nul-byte
 (end of string).  */

std::vector<uint8_t>
decode_binary_data (const char *str, int len)
{
    std::vector<uint8_t> bytes;
    if (len == 0)
    {
        return bytes;
    }
    if (len == -1)
        len = strlen (str);

    while (len--)
    {
        unsigned char c = *str;
        if (c == 0x7d && len > 0)
        {
            len--;
            str++;
            c ^= 0x20;
        }
        bytes.push_back (c);
    }
    return bytes;
}

typedef struct register_map_entry
{
    uint32_t        gdb_regnum; // gdb register number
    uint32_t        gdb_size;   // gdb register size in bytes (can be greater than or less than to debugnub size...)
    const char *    gdb_name;   // gdb register name
    DNBRegisterInfo nub_info;   // debugnub register info
    const uint8_t*  fail_value; // Value to print if case we fail to reg this register (if this is NULL, we will return an error)
    int             expedite;   // expedite delivery of this register in last stop reply packets
} register_map_entry_t;



// If the notion of registers differs from what is handed out by the
// architecture, then flavors can be defined here.

static const uint32_t MAX_REGISTER_BYTE_SIZE = 16;
static const uint8_t k_zero_bytes[MAX_REGISTER_BYTE_SIZE] = {0};
static std::vector<register_map_entry_t> g_dynamic_register_map;
static register_map_entry_t *g_reg_entries = NULL;
static size_t g_num_reg_entries = 0;

static void
RegisterEntryNotAvailable (register_map_entry_t *reg_entry)
{
    reg_entry->fail_value = k_zero_bytes;
    reg_entry->nub_info.set = INVALID_NUB_REGNUM;
    reg_entry->nub_info.reg = INVALID_NUB_REGNUM;
    reg_entry->nub_info.name = NULL;
    reg_entry->nub_info.alt = NULL;
    reg_entry->nub_info.type = InvalidRegType;
    reg_entry->nub_info.format = InvalidRegFormat;
    reg_entry->nub_info.size = 0;
    reg_entry->nub_info.offset = 0;
    reg_entry->nub_info.reg_gcc = INVALID_NUB_REGNUM;
    reg_entry->nub_info.reg_dwarf = INVALID_NUB_REGNUM;
    reg_entry->nub_info.reg_generic = INVALID_NUB_REGNUM;
    reg_entry->nub_info.reg_gdb = INVALID_NUB_REGNUM;
}


//----------------------------------------------------------------------
// ARM regiseter sets as gdb knows them
//----------------------------------------------------------------------
register_map_entry_t
g_gdb_register_map_arm[] =
{
    {  0,  4,  "r0",    {0}, NULL, 1},
    {  1,  4,  "r1",    {0}, NULL, 1},
    {  2,  4,  "r2",    {0}, NULL, 1},
    {  3,  4,  "r3",    {0}, NULL, 1},
    {  4,  4,  "r4",    {0}, NULL, 1},
    {  5,  4,  "r5",    {0}, NULL, 1},
    {  6,  4,  "r6",    {0}, NULL, 1},
    {  7,  4,  "r7",    {0}, NULL, 1},
    {  8,  4,  "r8",    {0}, NULL, 1},
    {  9,  4,  "r9",    {0}, NULL, 1},
    { 10,  4, "r10",    {0}, NULL, 1},
    { 11,  4, "r11",    {0}, NULL, 1},
    { 12,  4, "r12",    {0}, NULL, 1},
    { 13,  4,  "sp",    {0}, NULL, 1},
    { 14,  4,  "lr",    {0}, NULL, 1},
    { 15,  4,  "pc",    {0}, NULL, 1},
    { 16,  4,"cpsr",    {0}, NULL, 1},               // current program status register
    { 17,  4,  "s0",    {0}, NULL, 0},
    { 18,  4,  "s1",    {0}, NULL, 0},
    { 19,  4,  "s2",    {0}, NULL, 0},
    { 20,  4,  "s3",    {0}, NULL, 0},
    { 21,  4,  "s4",    {0}, NULL, 0},
    { 22,  4,  "s5",    {0}, NULL, 0},
    { 23,  4,  "s6",    {0}, NULL, 0},
    { 24,  4,  "s7",    {0}, NULL, 0},
    { 25,  4,  "s8",    {0}, NULL, 0},
    { 26,  4,  "s9",    {0}, NULL, 0},
    { 27,  4, "s10",    {0}, NULL, 0},
    { 28,  4, "s11",    {0}, NULL, 0},
    { 29,  4, "s12",    {0}, NULL, 0},
    { 30,  4, "s13",    {0}, NULL, 0},
    { 31,  4, "s14",    {0}, NULL, 0},
    { 32,  4, "s15",    {0}, NULL, 0},
    { 33,  4, "s16",    {0}, NULL, 0},
    { 34,  4, "s17",    {0}, NULL, 0},
    { 35,  4, "s18",    {0}, NULL, 0},
    { 36,  4, "s19",    {0}, NULL, 0},
    { 37,  4, "s20",    {0}, NULL, 0},
    { 38,  4, "s21",    {0}, NULL, 0},
    { 39,  4, "s22",    {0}, NULL, 0},
    { 40,  4, "s23",    {0}, NULL, 0},
    { 41,  4, "s24",    {0}, NULL, 0},
    { 42,  4, "s25",    {0}, NULL, 0},
    { 43,  4, "s26",    {0}, NULL, 0},
    { 44,  4, "s27",    {0}, NULL, 0},
    { 45,  4, "s28",    {0}, NULL, 0},
    { 46,  4, "s29",    {0}, NULL, 0},
    { 47,  4, "s30",    {0}, NULL, 0},
    { 48,  4, "s31",    {0}, NULL, 0},
    { 49,  8, "d0",     {0}, NULL, 0},
    { 50,  8, "d1",     {0}, NULL, 0},
    { 51,  8, "d2",     {0}, NULL, 0},
    { 52,  8, "d3",     {0}, NULL, 0},
    { 53,  8, "d4",     {0}, NULL, 0},
    { 54,  8, "d5",     {0}, NULL, 0},
    { 55,  8, "d6",     {0}, NULL, 0},
    { 56,  8, "d7",     {0}, NULL, 0},
    { 57,  8, "d8",     {0}, NULL, 0},
    { 58,  8, "d9",     {0}, NULL, 0},
    { 59,  8, "d10",    {0}, NULL, 0},
    { 60,  8, "d11",    {0}, NULL, 0},
    { 61,  8, "d12",    {0}, NULL, 0},
    { 62,  8, "d13",    {0}, NULL, 0},
    { 63,  8, "d14",    {0}, NULL, 0},
    { 64,  8, "d15",    {0}, NULL, 0},
    { 65,  8, "d16",    {0}, NULL, 0},
    { 66,  8, "d17",    {0}, NULL, 0},
    { 67,  8, "d18",    {0}, NULL, 0},
    { 68,  8, "d19",    {0}, NULL, 0},
    { 69,  8, "d20",    {0}, NULL, 0},
    { 70,  8, "d21",    {0}, NULL, 0},
    { 71,  8, "d22",    {0}, NULL, 0},
    { 72,  8, "d23",    {0}, NULL, 0},
    { 73,  8, "d24",    {0}, NULL, 0},
    { 74,  8, "d25",    {0}, NULL, 0},
    { 75,  8, "d26",    {0}, NULL, 0},
    { 76,  8, "d27",    {0}, NULL, 0},
    { 77,  8, "d28",    {0}, NULL, 0},
    { 78,  8, "d29",    {0}, NULL, 0},
    { 79,  8, "d30",    {0}, NULL, 0},
    { 80,  8, "d31",    {0}, NULL, 0},
    { 81, 16, "q0",     {0}, NULL, 0},
    { 82, 16, "q1",     {0}, NULL, 0},
    { 83, 16, "q2",     {0}, NULL, 0},
    { 84, 16, "q3",     {0}, NULL, 0},
    { 85, 16, "q4",     {0}, NULL, 0},
    { 86, 16, "q5",     {0}, NULL, 0},
    { 87, 16, "q6",     {0}, NULL, 0},
    { 88, 16, "q7",     {0}, NULL, 0},
    { 89, 16, "q8",     {0}, NULL, 0},
    { 90, 16, "q9",     {0}, NULL, 0},
    { 91, 16, "q10",    {0}, NULL, 0},
    { 92, 16, "q11",    {0}, NULL, 0},
    { 93, 16, "q12",    {0}, NULL, 0},
    { 94, 16, "q13",    {0}, NULL, 0},
    { 95, 16, "q14",    {0}, NULL, 0},
    { 96, 16, "q15",    {0}, NULL, 0},
    { 97,  4, "fpscr",  {0}, NULL, 0}
};

register_map_entry_t
g_gdb_register_map_i386[] =
{
    {  0,   4, "eax"    , {0}, NULL, 0 },
    {  1,   4, "ecx"    , {0}, NULL, 0 },
    {  2,   4, "edx"    , {0}, NULL, 0 },
    {  3,   4, "ebx"    , {0}, NULL, 0 },
    {  4,   4, "esp"    , {0}, NULL, 1 },
    {  5,   4, "ebp"    , {0}, NULL, 1 },
    {  6,   4, "esi"    , {0}, NULL, 0 },
    {  7,   4, "edi"    , {0}, NULL, 0 },
    {  8,   4, "eip"    , {0}, NULL, 1 },
    {  9,   4, "eflags" , {0}, NULL, 0 },
    { 10,   4, "cs"     , {0}, NULL, 0 },
    { 11,   4, "ss"     , {0}, NULL, 0 },
    { 12,   4, "ds"     , {0}, NULL, 0 },
    { 13,   4, "es"     , {0}, NULL, 0 },
    { 14,   4, "fs"     , {0}, NULL, 0 },
    { 15,   4, "gs"     , {0}, NULL, 0 },
    { 16,  10, "stmm0"  , {0}, NULL, 0 },
    { 17,  10, "stmm1"  , {0}, NULL, 0 },
    { 18,  10, "stmm2"  , {0}, NULL, 0 },
    { 19,  10, "stmm3"  , {0}, NULL, 0 },
    { 20,  10, "stmm4"  , {0}, NULL, 0 },
    { 21,  10, "stmm5"  , {0}, NULL, 0 },
    { 22,  10, "stmm6"  , {0}, NULL, 0 },
    { 23,  10, "stmm7"  , {0}, NULL, 0 },
    { 24,   4, "fctrl"  , {0}, NULL, 0 },
    { 25,   4, "fstat"  , {0}, NULL, 0 },
    { 26,   4, "ftag"   , {0}, NULL, 0 },
    { 27,   4, "fiseg"  , {0}, NULL, 0 },
    { 28,   4, "fioff"  , {0}, NULL, 0 },
    { 29,   4, "foseg"  , {0}, NULL, 0 },
    { 30,   4, "fooff"  , {0}, NULL, 0 },
    { 31,   4, "fop"    , {0}, NULL, 0 },
    { 32,  16, "xmm0"   , {0}, NULL, 0 },
    { 33,  16, "xmm1"   , {0}, NULL, 0 },
    { 34,  16, "xmm2"   , {0}, NULL, 0 },
    { 35,  16, "xmm3"   , {0}, NULL, 0 },
    { 36,  16, "xmm4"   , {0}, NULL, 0 },
    { 37,  16, "xmm5"   , {0}, NULL, 0 },
    { 38,  16, "xmm6"   , {0}, NULL, 0 },
    { 39,  16, "xmm7"   , {0}, NULL, 0 },
    { 40,   4, "mxcsr"  , {0}, NULL, 0 },
};

register_map_entry_t
g_gdb_register_map_x86_64[] =
{
    {  0,   8, "rax"   , {0}, NULL, 0 },
    {  1,   8, "rbx"   , {0}, NULL, 0 },
    {  2,   8, "rcx"   , {0}, NULL, 0 },
    {  3,   8, "rdx"   , {0}, NULL, 0 },
    {  4,   8, "rsi"   , {0}, NULL, 0 },
    {  5,   8, "rdi"   , {0}, NULL, 0 },
    {  6,   8, "rbp"   , {0}, NULL, 1 },
    {  7,   8, "rsp"   , {0}, NULL, 1 },
    {  8,   8, "r8"    , {0}, NULL, 0 },
    {  9,   8, "r9"    , {0}, NULL, 0 },
    { 10,   8, "r10"   , {0}, NULL, 0 },
    { 11,   8, "r11"   , {0}, NULL, 0 },
    { 12,   8, "r12"   , {0}, NULL, 0 },
    { 13,   8, "r13"   , {0}, NULL, 0 },
    { 14,   8, "r14"   , {0}, NULL, 0 },
    { 15,   8, "r15"   , {0}, NULL, 0 },
    { 16,   8, "rip"   , {0}, NULL, 1 },
    { 17,   4, "rflags", {0}, NULL, 0 },
    { 18,   4, "cs"    , {0}, NULL, 0 },
    { 19,   4, "ss"    , {0}, NULL, 0 },
    { 20,   4, "ds"    , {0}, NULL, 0 },
    { 21,   4, "es"    , {0}, NULL, 0 },
    { 22,   4, "fs"    , {0}, NULL, 0 },
    { 23,   4, "gs"    , {0}, NULL, 0 },
    { 24,  10, "stmm0" , {0}, NULL, 0 },
    { 25,  10, "stmm1" , {0}, NULL, 0 },
    { 26,  10, "stmm2" , {0}, NULL, 0 },
    { 27,  10, "stmm3" , {0}, NULL, 0 },
    { 28,  10, "stmm4" , {0}, NULL, 0 },
    { 29,  10, "stmm5" , {0}, NULL, 0 },
    { 30,  10, "stmm6" , {0}, NULL, 0 },
    { 31,  10, "stmm7" , {0}, NULL, 0 },
    { 32,   4, "fctrl" , {0}, NULL, 0 },
    { 33,   4, "fstat" , {0}, NULL, 0 },
    { 34,   4, "ftag"  , {0}, NULL, 0 },
    { 35,   4, "fiseg" , {0}, NULL, 0 },
    { 36,   4, "fioff" , {0}, NULL, 0 },
    { 37,   4, "foseg" , {0}, NULL, 0 },
    { 38,   4, "fooff" , {0}, NULL, 0 },
    { 39,   4, "fop"   , {0}, NULL, 0 },
    { 40,  16, "xmm0"  , {0}, NULL, 0 },
    { 41,  16, "xmm1"  , {0}, NULL, 0 },
    { 42,  16, "xmm2"  , {0}, NULL, 0 },
    { 43,  16, "xmm3"  , {0}, NULL, 0 },
    { 44,  16, "xmm4"  , {0}, NULL, 0 },
    { 45,  16, "xmm5"  , {0}, NULL, 0 },
    { 46,  16, "xmm6"  , {0}, NULL, 0 },
    { 47,  16, "xmm7"  , {0}, NULL, 0 },
    { 48,  16, "xmm8"  , {0}, NULL, 0 },
    { 49,  16, "xmm9"  , {0}, NULL, 0 },
    { 50,  16, "xmm10" , {0}, NULL, 0 },
    { 51,  16, "xmm11" , {0}, NULL, 0 },
    { 52,  16, "xmm12" , {0}, NULL, 0 },
    { 53,  16, "xmm13" , {0}, NULL, 0 },
    { 54,  16, "xmm14" , {0}, NULL, 0 },
    { 55,  16, "xmm15" , {0}, NULL, 0 },
    { 56,   4, "mxcsr" , {0}, NULL, 0 }
};


void
RNBRemote::Initialize()
{
    DNBInitialize();
}


bool
RNBRemote::InitializeRegisters (bool force)
{
    pid_t pid = m_ctx.ProcessID();
    if (pid == INVALID_NUB_PROCESS)
        return false;

    if (m_use_native_regs)
    {
        DNBLogThreadedIf (LOG_RNB_PROC, "RNBRemote::%s() getting native registers from DNB interface", __FUNCTION__);
        // Discover the registers by querying the DNB interface and letting it
        // state the registers that it would like to export. This allows the
        // registers to be discovered using multiple qRegisterInfo calls to get
        // all register information after the architecture for the process is
        // determined.
        if (force)
        {
            g_dynamic_register_map.clear();
            g_reg_entries = NULL;
            g_num_reg_entries = 0;
        }

        if (g_dynamic_register_map.empty())
        {
            nub_size_t num_reg_sets = 0;
            const DNBRegisterSetInfo *reg_sets = DNBGetRegisterSetInfo (&num_reg_sets);

            assert (num_reg_sets > 0 && reg_sets != NULL);

            uint32_t regnum = 0;
            for (nub_size_t set = 0; set < num_reg_sets; ++set)
            {
                if (reg_sets[set].registers == NULL)
                    continue;

                for (uint32_t reg=0; reg < reg_sets[set].num_registers; ++reg)
                {
                    register_map_entry_t reg_entry = {
                        regnum++,                           // register number starts at zero and goes up with no gaps
                        reg_sets[set].registers[reg].size,  // register size in bytes
                        reg_sets[set].registers[reg].name,  // register name
                        reg_sets[set].registers[reg],       // DNBRegisterInfo
                        NULL,                               // Value to print if case we fail to reg this register (if this is NULL, we will return an error)
                        reg_sets[set].registers[reg].reg_generic != INVALID_NUB_REGNUM};

                    g_dynamic_register_map.push_back (reg_entry);
                }
            }
            g_reg_entries = g_dynamic_register_map.data();
            g_num_reg_entries = g_dynamic_register_map.size();
        }
        return true;
    }
    else
    {
        uint32_t cpu_type = DNBProcessGetCPUType (pid);
        DNBLogThreadedIf (LOG_RNB_PROC, "RNBRemote::%s() getting gdb registers(%s)", __FUNCTION__, m_arch.c_str());
#if defined (__i386__) || defined (__x86_64__)
        if (cpu_type == CPU_TYPE_X86_64)
        {
            const size_t num_regs = sizeof (g_gdb_register_map_x86_64) / sizeof (register_map_entry_t);
            for (uint32_t i=0; i<num_regs; ++i)
            {
                if (!DNBGetRegisterInfoByName (g_gdb_register_map_x86_64[i].gdb_name, &g_gdb_register_map_x86_64[i].nub_info))
                {
                    RegisterEntryNotAvailable (&g_gdb_register_map_x86_64[i]);
                    assert (g_gdb_register_map_x86_64[i].gdb_size < MAX_REGISTER_BYTE_SIZE);
                }
            }
            g_reg_entries = g_gdb_register_map_x86_64;
            g_num_reg_entries = sizeof (g_gdb_register_map_x86_64) / sizeof (register_map_entry_t);
            return true;
        }
        else if (cpu_type == CPU_TYPE_I386)
        {
            const size_t num_regs = sizeof (g_gdb_register_map_i386) / sizeof (register_map_entry_t);
            for (uint32_t i=0; i<num_regs; ++i)
            {
                if (!DNBGetRegisterInfoByName (g_gdb_register_map_i386[i].gdb_name, &g_gdb_register_map_i386[i].nub_info))
                {
                    RegisterEntryNotAvailable (&g_gdb_register_map_i386[i]);
                    assert (g_gdb_register_map_i386[i].gdb_size <= MAX_REGISTER_BYTE_SIZE);
                }
            }
            g_reg_entries = g_gdb_register_map_i386;
            g_num_reg_entries = sizeof (g_gdb_register_map_i386) / sizeof (register_map_entry_t);
            return true;
        }
#elif defined (__arm__)
        if (cpu_type == CPU_TYPE_ARM)
        {
            const size_t num_regs = sizeof (g_gdb_register_map_arm) / sizeof (register_map_entry_t);
            for (uint32_t i=0; i<num_regs; ++i)
            {
                if (!DNBGetRegisterInfoByName (g_gdb_register_map_arm[i].gdb_name, &g_gdb_register_map_arm[i].nub_info))
                {
                    RegisterEntryNotAvailable (&g_gdb_register_map_arm[i]);
                    assert (g_gdb_register_map_arm[i].gdb_size <= MAX_REGISTER_BYTE_SIZE);
                }
            }
            g_reg_entries = g_gdb_register_map_arm;
            g_num_reg_entries = sizeof (g_gdb_register_map_arm) / sizeof (register_map_entry_t);
            return true;
        }
#endif
    }
    return false;
}

/* The inferior has stopped executing; send a packet
 to gdb to let it know.  */

void
RNBRemote::NotifyThatProcessStopped (void)
{
    RNBRemote::HandlePacket_last_signal (NULL);
    return;
}


/* 'A arglen,argnum,arg,...'
 Update the inferior context CTX with the program name and arg
 list.
 The documentation for this packet is underwhelming but my best reading
 of this is that it is a series of (len, position #, arg)'s, one for
 each argument with "arg" hex encoded (two 0-9a-f chars?).
 Why we need BOTH a "len" and a hex encoded "arg" is beyond me - either
 is sufficient to get around the "," position separator escape issue.

 e.g. our best guess for a valid 'A' packet for "gdb -q a.out" is

 6,0,676462,4,1,2d71,10,2,612e6f7574

 Note that "argnum" and "arglen" are numbers in base 10.  Again, that's
 not documented either way but I'm assuming it's so.  */

rnb_err_t
RNBRemote::HandlePacket_A (const char *p)
{
    if (p == NULL || *p == '\0')
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Null packet for 'A' pkt");
    }
    p++;
    if (p == '\0' || !isdigit (*p))
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "arglen not specified on 'A' pkt");
    }

    /* I promise I don't modify it anywhere in this function.  strtoul()'s
     2nd arg has to be non-const which makes it problematic to step
     through the string easily.  */
    char *buf = const_cast<char *>(p);

    RNBContext& ctx = Context();

    while (*buf != '\0')
    {
        int arglen, argnum;
        std::string arg;
        char *c;

        errno = 0;
        arglen = strtoul (buf, &c, 10);
        if (errno != 0 && arglen == 0)
        {
            return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "arglen not a number on 'A' pkt");
        }
        if (*c != ',')
        {
            return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "arglen not followed by comma on 'A' pkt");
        }
        buf = c + 1;

        errno = 0;
        argnum = strtoul (buf, &c, 10);
        if (errno != 0 && argnum == 0)
        {
            return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "argnum not a number on 'A' pkt");
        }
        if (*c != ',')
        {
            return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "arglen not followed by comma on 'A' pkt");
        }
        buf = c + 1;

        c = buf;
        buf = buf + arglen;
        while (c < buf && *c != '\0' && c + 1 < buf && *(c + 1) != '\0')
        {
            char smallbuf[3];
            smallbuf[0] = *c;
            smallbuf[1] = *(c + 1);
            smallbuf[2] = '\0';

            errno = 0;
            int ch = strtoul (smallbuf, NULL, 16);
            if (errno != 0 && ch == 0)
            {
                return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "non-hex char in arg on 'A' pkt");
            }

            arg.push_back(ch);
            c += 2;
        }

        ctx.PushArgument (arg.c_str());
        if (*buf == ',')
            buf++;
    }
    SendPacket ("OK");

    return rnb_success;
}

/* 'H c t'
 Set the thread for subsequent actions; 'c' for step/continue ops,
 'g' for other ops.  -1 means all threads, 0 means any thread.  */

rnb_err_t
RNBRemote::HandlePacket_H (const char *p)
{
    p++;  // skip 'H'
    if (*p != 'c' && *p != 'g')
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Missing 'c' or 'g' type in H packet");
    }

    if (!m_ctx.HasValidProcessID())
    {
        // We allow gdb to connect to a server that hasn't started running
        // the target yet.  gdb still wants to ask questions about it and
        // freaks out if it gets an error.  So just return OK here.
    }

    errno = 0;
    nub_thread_t tid = strtoul (p + 1, NULL, 16);
    if (errno != 0 && tid == 0)
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Invalid thread number in H packet");
    }
    if (*p == 'c')
        SetContinueThread (tid);
    if (*p == 'g')
        SetCurrentThread (tid);

    return SendPacket ("OK");
}


rnb_err_t
RNBRemote::HandlePacket_qLaunchSuccess (const char *p)
{
    if (m_ctx.HasValidProcessID() || m_ctx.LaunchStatus().Error() == 0)
        return SendPacket("OK");
    std::ostringstream ret_str;
    std::string status_str;
    ret_str << "E" << m_ctx.LaunchStatusAsString(status_str);

    return SendPacket (ret_str.str());
}

rnb_err_t
RNBRemote::HandlePacket_qShlibInfoAddr (const char *p)
{
    if (m_ctx.HasValidProcessID())
    {
        nub_addr_t shlib_info_addr = DNBProcessGetSharedLibraryInfoAddress(m_ctx.ProcessID());
        if (shlib_info_addr != INVALID_NUB_ADDRESS)
        {
            std::ostringstream ostrm;
            ostrm << RAW_HEXBASE << shlib_info_addr;
            return SendPacket (ostrm.str ());
        }
    }
    return SendPacket ("E44");
}

rnb_err_t
RNBRemote::HandlePacket_qStepPacketSupported (const char *p)
{
    // Normally the "s" packet is mandatory, yet in gdb when using ARM, they
    // get around the need for this packet by implementing software single
    // stepping from gdb. Current versions of debugserver do support the "s"
    // packet, yet some older versions do not. We need a way to tell if this
    // packet is supported so we can disable software single stepping in gdb
    // for remote targets (so the "s" packet will get used).
    return SendPacket("OK");
}

rnb_err_t
RNBRemote::HandlePacket_qSyncThreadStateSupported (const char *p)
{
    // We support attachOrWait meaning attach if the process exists, otherwise wait to attach.
    return SendPacket("OK");
}

rnb_err_t
RNBRemote::HandlePacket_qVAttachOrWaitSupported (const char *p)
{
    // We support attachOrWait meaning attach if the process exists, otherwise wait to attach.
    return SendPacket("OK");
}

rnb_err_t
RNBRemote::HandlePacket_qThreadStopInfo (const char *p)
{
    p += strlen ("qThreadStopInfo");
    nub_thread_t tid = strtoul(p, 0, 16);
    return SendStopReplyPacketForThread (tid);
}

rnb_err_t
RNBRemote::HandlePacket_qThreadInfo (const char *p)
{
    // We allow gdb to connect to a server that hasn't started running
    // the target yet.  gdb still wants to ask questions about it and
    // freaks out if it gets an error.  So just return OK here.
    nub_process_t pid = m_ctx.ProcessID();
    if (pid == INVALID_NUB_PROCESS)
        return SendPacket ("OK");

    // Only "qfThreadInfo" and "qsThreadInfo" get into this function so
    // we only need to check the second byte to tell which is which
    if (p[1] == 'f')
    {
        nub_size_t numthreads = DNBProcessGetNumThreads (pid);
        std::ostringstream ostrm;
        ostrm << "m";
        bool first = true;
        for (nub_size_t i = 0; i < numthreads; ++i)
        {
            if (first)
                first = false;
            else
                ostrm << ",";
            nub_thread_t th = DNBProcessGetThreadAtIndex (pid, i);
            ostrm << std::hex << th;
        }
        return SendPacket (ostrm.str ());
    }
    else
    {
        return SendPacket ("l");
    }
}

rnb_err_t
RNBRemote::HandlePacket_qThreadExtraInfo (const char *p)
{
    // We allow gdb to connect to a server that hasn't started running
    // the target yet.  gdb still wants to ask questions about it and
    // freaks out if it gets an error.  So just return OK here.
    nub_process_t pid = m_ctx.ProcessID();
    if (pid == INVALID_NUB_PROCESS)
        return SendPacket ("OK");

    /* This is supposed to return a string like 'Runnable' or
     'Blocked on Mutex'.
     The returned string is formatted like the "A" packet - a
     sequence of letters encoded in as 2-hex-chars-per-letter.  */
    p += strlen ("qThreadExtraInfo");
    if (*p++ != ',')
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Illformed qThreadExtraInfo packet");
    errno = 0;
    nub_thread_t tid = strtoul (p, NULL, 16);
    if (errno != 0 && tid == 0)
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Invalid thread number in qThreadExtraInfo packet");
    }

    const char * threadInfo = DNBThreadGetInfo(pid, tid);
    if (threadInfo != NULL && threadInfo[0])
    {
        return SendHexEncodedBytePacket(NULL, threadInfo, strlen(threadInfo), NULL);
    }
    else
    {
        // "OK" == 4f6b
        // Return "OK" as a ASCII hex byte stream if things go wrong
        return SendPacket ("4f6b");
    }

    return SendPacket ("");
}


const char *k_space_delimiters = " \t";
static void
skip_spaces (std::string &line)
{
    if (!line.empty())
    {
        size_t space_pos = line.find_first_not_of (k_space_delimiters);
        if (space_pos > 0)
            line.erase(0, space_pos);
    }
}

static std::string
get_identifier (std::string &line)
{
    std::string word;
    skip_spaces (line);
    const size_t line_size = line.size();
    size_t end_pos;
    for (end_pos = 0; end_pos < line_size; ++end_pos)
    {
        if (end_pos == 0)
        {
            if (isalpha(line[end_pos]) || line[end_pos] == '_')
                continue;
        }
        else if (isalnum(line[end_pos]) || line[end_pos] == '_')
            continue;
        break;
    }
    word.assign (line, 0, end_pos);
    line.erase(0, end_pos);
    return word;
}

static std::string
get_operator (std::string &line)
{
    std::string op;
    skip_spaces (line);
    if (!line.empty())
    {
        if (line[0] == '=')
        {
            op = '=';
            line.erase(0,1);
        }
    }
    return op;
}

static std::string
get_value (std::string &line)
{
    std::string value;
    skip_spaces (line);
    if (!line.empty())
    {
        value.swap(line);
    }
    return value;
}


extern void FileLogCallback(void *baton, uint32_t flags, const char *format, va_list args);
extern void ASLLogCallback(void *baton, uint32_t flags, const char *format, va_list args);

rnb_err_t
RNBRemote::HandlePacket_qRcmd (const char *p)
{
    const char *c = p + strlen("qRcmd,");
    std::string line;
    while (c[0] && c[1])
    {
        char smallbuf[3] = { c[0], c[1], '\0' };
        errno = 0;
        int ch = strtoul (smallbuf, NULL, 16);
        if (errno != 0 && ch == 0)
            return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "non-hex char in payload of qRcmd packet");
        line.push_back(ch);
        c += 2;
    }
    if (*c == '\0')
    {
        std::string command = get_identifier(line);
        if (command.compare("set") == 0)
        {
            std::string variable = get_identifier (line);
            std::string op = get_operator (line);
            std::string value = get_value (line);
            if (variable.compare("logfile") == 0)
            {
                FILE *log_file = fopen(value.c_str(), "w");
                if (log_file)
                {
                    DNBLogSetLogCallback(FileLogCallback, log_file);
                    return SendPacket ("OK");
                }
                return SendPacket ("E71");
            }
            else if (variable.compare("logmask") == 0)
            {
                char *end;
                errno = 0;
                uint32_t logmask = strtoul (value.c_str(), &end, 0);
                if (errno == 0 && end && *end == '\0')
                {
                    DNBLogSetLogMask (logmask);
                    if (!DNBLogGetLogCallback())
                        DNBLogSetLogCallback(ASLLogCallback, NULL);
                    return SendPacket ("OK");
                }
                errno = 0;
                logmask = strtoul (value.c_str(), &end, 16);
                if (errno == 0 && end && *end == '\0')
                {
                    DNBLogSetLogMask (logmask);
                    return SendPacket ("OK");
                }
                return SendPacket ("E72");
            }
            return SendPacket ("E70");
        }
        return SendPacket ("E69");
    }
    return SendPacket ("E73");
}

rnb_err_t
RNBRemote::HandlePacket_qC (const char *p)
{
    nub_process_t pid;
    std::ostringstream rep;
    // If we haven't run the process yet, we tell the debugger the
    // pid is 0.  That way it can know to tell use to run later on.
    if (m_ctx.HasValidProcessID())
        pid = m_ctx.ProcessID();
    else
        pid = 0;
    rep << "QC" << std::hex << pid;
    return SendPacket (rep.str());
}

rnb_err_t
RNBRemote::HandlePacket_qGetPid (const char *p)
{
    nub_process_t pid;
    std::ostringstream rep;
    // If we haven't run the process yet, we tell the debugger the
    // pid is 0.  That way it can know to tell use to run later on.
    if (m_ctx.HasValidProcessID())
        pid = m_ctx.ProcessID();
    else
        pid = 0;
    rep << std::hex << pid;
    return SendPacket (rep.str());
}

rnb_err_t
RNBRemote::HandlePacket_qRegisterInfo (const char *p)
{
    if (g_num_reg_entries == 0)
        InitializeRegisters ();

    p += strlen ("qRegisterInfo");

    nub_size_t num_reg_sets = 0;
    const DNBRegisterSetInfo *reg_set_info = DNBGetRegisterSetInfo (&num_reg_sets);
    uint32_t reg_num = strtoul(p, 0, 16);

    if (reg_num < g_num_reg_entries)
    {
        const register_map_entry_t *reg_entry = &g_reg_entries[reg_num];
        std::ostringstream ostrm;
        ostrm << "name:" << reg_entry->gdb_name << ';';

        if (reg_entry->nub_info.name && ::strcmp (reg_entry->gdb_name, reg_entry->nub_info.name))
            ostrm << "alt-name:" << reg_entry->nub_info.name << ';';
        else if (reg_entry->nub_info.alt && ::strcmp (reg_entry->gdb_name, reg_entry->nub_info.alt))
            ostrm << "alt-name:" << reg_entry->nub_info.alt << ';';

        ostrm << "bitsize:" << std::dec << reg_entry->gdb_size * 8 << ';';
        ostrm << "offset:" << std::dec << reg_entry->nub_info.offset << ';';

        switch (reg_entry->nub_info.type)
        {
            case Uint:      ostrm << "encoding:uint;"; break;
            case Sint:      ostrm << "encoding:sint;"; break;
            case IEEE754:   ostrm << "encoding:ieee754;"; break;
            case Vector:    ostrm << "encoding:vector;"; break;
        }

        switch (reg_entry->nub_info.format)
        {
            case Binary:            ostrm << "format:binary;"; break;
            case Decimal:           ostrm << "format:decimal;"; break;
            case Hex:               ostrm << "format:hex;"; break;
            case Float:             ostrm << "format:float;"; break;
            case VectorOfSInt8:     ostrm << "format:vector-sint8;"; break;
            case VectorOfUInt8:     ostrm << "format:vector-uint8;"; break;
            case VectorOfSInt16:    ostrm << "format:vector-sint16;"; break;
            case VectorOfUInt16:    ostrm << "format:vector-uint16;"; break;
            case VectorOfSInt32:    ostrm << "format:vector-sint32;"; break;
            case VectorOfUInt32:    ostrm << "format:vector-uint32;"; break;
            case VectorOfFloat32:   ostrm << "format:vector-float32;"; break;
            case VectorOfUInt128:   ostrm << "format:vector-uint128;"; break;
        };

        if (reg_set_info && reg_entry->nub_info.set < num_reg_sets)
            ostrm << "set:" << reg_set_info[reg_entry->nub_info.set].name << ';';


        if (g_reg_entries != g_dynamic_register_map.data())
        {
            if (reg_entry->nub_info.reg_gdb != INVALID_NUB_REGNUM && reg_entry->nub_info.reg_gdb != reg_num)
            {
                printf("register %s is getting gdb reg_num of %u when the register info says %u\n",
                       reg_entry->gdb_name, reg_num, reg_entry->nub_info.reg_gdb);
            }
        }

        if (reg_entry->nub_info.reg_gcc != INVALID_NUB_REGNUM)
            ostrm << "gcc:" << std::dec << reg_entry->nub_info.reg_gcc << ';';

        if (reg_entry->nub_info.reg_dwarf != INVALID_NUB_REGNUM)
            ostrm << "dwarf:" << std::dec << reg_entry->nub_info.reg_dwarf << ';';


        switch (reg_entry->nub_info.reg_generic)
        {
            case GENERIC_REGNUM_FP:     ostrm << "generic:fp;"; break;
            case GENERIC_REGNUM_PC:     ostrm << "generic:pc;"; break;
            case GENERIC_REGNUM_SP:     ostrm << "generic:sp;"; break;
            case GENERIC_REGNUM_RA:     ostrm << "generic:ra;"; break;
            case GENERIC_REGNUM_FLAGS:  ostrm << "generic:flags;"; break;
            case GENERIC_REGNUM_ARG1:   ostrm << "generic:arg1;"; break;
            case GENERIC_REGNUM_ARG2:   ostrm << "generic:arg2;"; break;
            case GENERIC_REGNUM_ARG3:   ostrm << "generic:arg3;"; break;
            case GENERIC_REGNUM_ARG4:   ostrm << "generic:arg4;"; break;
            case GENERIC_REGNUM_ARG5:   ostrm << "generic:arg5;"; break;
            case GENERIC_REGNUM_ARG6:   ostrm << "generic:arg6;"; break;
            case GENERIC_REGNUM_ARG7:   ostrm << "generic:arg7;"; break;
            case GENERIC_REGNUM_ARG8:   ostrm << "generic:arg8;"; break;
            default: break;
        }
        
        if (reg_entry->nub_info.pseudo_regs && reg_entry->nub_info.pseudo_regs[0] != INVALID_NUB_REGNUM)
        {
            ostrm << "container-regs:";
            for (unsigned i=0; reg_entry->nub_info.pseudo_regs[i] != INVALID_NUB_REGNUM; ++i)
            {
                if (i > 0)
                    ostrm << ',';
                ostrm << RAW_HEXBASE << reg_entry->nub_info.pseudo_regs[i];
            }
            ostrm << ';';
        }

        if (reg_entry->nub_info.update_regs && reg_entry->nub_info.update_regs[0] != INVALID_NUB_REGNUM)
        {
            ostrm << "invalidate-regs:";
            for (unsigned i=0; reg_entry->nub_info.update_regs[i] != INVALID_NUB_REGNUM; ++i)
            {
                if (i > 0)
                    ostrm << ',';
                ostrm << RAW_HEXBASE << reg_entry->nub_info.update_regs[i];
            }
            ostrm << ';';
        }

        return SendPacket (ostrm.str ());
    }
    return SendPacket ("E45");
}


/* This expects a packet formatted like

 QSetLogging:bitmask=LOG_ALL|LOG_RNB_REMOTE;

 with the "QSetLogging:" already removed from the start.  Maybe in the
 future this packet will include other keyvalue pairs like

 QSetLogging:bitmask=LOG_ALL;mode=asl;
 */

rnb_err_t
set_logging (const char *p)
{
    int bitmask = 0;
    while (p && *p != '\0')
    {
        if (strncmp (p, "bitmask=", sizeof ("bitmask=") - 1) == 0)
        {
            p += sizeof ("bitmask=") - 1;
            while (p && *p != '\0' && *p != ';')
            {
                if (*p == '|')
                    p++;

// to regenerate the LOG_ entries (not including the LOG_RNB entries)
// $ for logname in `grep '^#define LOG_' DNBDefs.h | egrep -v 'LOG_HI|LOG_LO' | awk '{print $2}'` 
// do 
//   echo "                else if (strncmp (p, \"$logname\", sizeof (\"$logname\") - 1) == 0)"
//   echo "                {" 
//   echo "                    p += sizeof (\"$logname\") - 1;"
//   echo "                    bitmask |= $logname;"
//   echo "                }"
// done
                if (strncmp (p, "LOG_VERBOSE", sizeof ("LOG_VERBOSE") - 1) == 0)
                {
                    p += sizeof ("LOG_VERBOSE") - 1;
                    bitmask |= LOG_VERBOSE;
                }
                else if (strncmp (p, "LOG_PROCESS", sizeof ("LOG_PROCESS") - 1) == 0)
                {
                    p += sizeof ("LOG_PROCESS") - 1;
                    bitmask |= LOG_PROCESS;
                }
                else if (strncmp (p, "LOG_THREAD", sizeof ("LOG_THREAD") - 1) == 0)
                {
                    p += sizeof ("LOG_THREAD") - 1;
                    bitmask |= LOG_THREAD;
                }
                else if (strncmp (p, "LOG_EXCEPTIONS", sizeof ("LOG_EXCEPTIONS") - 1) == 0)
                {
                    p += sizeof ("LOG_EXCEPTIONS") - 1;
                    bitmask |= LOG_EXCEPTIONS;
                }
                else if (strncmp (p, "LOG_SHLIB", sizeof ("LOG_SHLIB") - 1) == 0)
                {
                    p += sizeof ("LOG_SHLIB") - 1;
                    bitmask |= LOG_SHLIB;
                }
                else if (strncmp (p, "LOG_MEMORY", sizeof ("LOG_MEMORY") - 1) == 0)
                {
                    p += sizeof ("LOG_MEMORY") - 1;
                    bitmask |= LOG_MEMORY;
                }
                else if (strncmp (p, "LOG_MEMORY_DATA_SHORT", sizeof ("LOG_MEMORY_DATA_SHORT") - 1) == 0)
                {
                    p += sizeof ("LOG_MEMORY_DATA_SHORT") - 1;
                    bitmask |= LOG_MEMORY_DATA_SHORT;
                }
                else if (strncmp (p, "LOG_MEMORY_DATA_LONG", sizeof ("LOG_MEMORY_DATA_LONG") - 1) == 0)
                {
                    p += sizeof ("LOG_MEMORY_DATA_LONG") - 1;
                    bitmask |= LOG_MEMORY_DATA_LONG;
                }
                else if (strncmp (p, "LOG_MEMORY_PROTECTIONS", sizeof ("LOG_MEMORY_PROTECTIONS") - 1) == 0)
                {
                    p += sizeof ("LOG_MEMORY_PROTECTIONS") - 1;
                    bitmask |= LOG_MEMORY_PROTECTIONS;
                }
                else if (strncmp (p, "LOG_BREAKPOINTS", sizeof ("LOG_BREAKPOINTS") - 1) == 0)
                {
                    p += sizeof ("LOG_BREAKPOINTS") - 1;
                    bitmask |= LOG_BREAKPOINTS;
                }
                else if (strncmp (p, "LOG_EVENTS", sizeof ("LOG_EVENTS") - 1) == 0)
                {
                    p += sizeof ("LOG_EVENTS") - 1;
                    bitmask |= LOG_EVENTS;
                }
                else if (strncmp (p, "LOG_WATCHPOINTS", sizeof ("LOG_WATCHPOINTS") - 1) == 0)
                {
                    p += sizeof ("LOG_WATCHPOINTS") - 1;
                    bitmask |= LOG_WATCHPOINTS;
                }
                else if (strncmp (p, "LOG_STEP", sizeof ("LOG_STEP") - 1) == 0)
                {
                    p += sizeof ("LOG_STEP") - 1;
                    bitmask |= LOG_STEP;
                }
                else if (strncmp (p, "LOG_TASK", sizeof ("LOG_TASK") - 1) == 0)
                {
                    p += sizeof ("LOG_TASK") - 1;
                    bitmask |= LOG_TASK;
                }
                else if (strncmp (p, "LOG_ALL", sizeof ("LOG_ALL") - 1) == 0)
                {
                    p += sizeof ("LOG_ALL") - 1;
                    bitmask |= LOG_ALL;
                }
                else if (strncmp (p, "LOG_DEFAULT", sizeof ("LOG_DEFAULT") - 1) == 0)
                {
                    p += sizeof ("LOG_DEFAULT") - 1;
                    bitmask |= LOG_DEFAULT;
                }
// end of auto-generated entries

                else if (strncmp (p, "LOG_NONE", sizeof ("LOG_NONE") - 1) == 0)
                {
                    p += sizeof ("LOG_NONE") - 1;
                    bitmask = 0;
                }
                else if (strncmp (p, "LOG_RNB_MINIMAL", sizeof ("LOG_RNB_MINIMAL") - 1) == 0)
                {
                    p += sizeof ("LOG_RNB_MINIMAL") - 1;
                    bitmask |= LOG_RNB_MINIMAL;
                }
                else if (strncmp (p, "LOG_RNB_MEDIUM", sizeof ("LOG_RNB_MEDIUM") - 1) == 0)
                {
                    p += sizeof ("LOG_RNB_MEDIUM") - 1;
                    bitmask |= LOG_RNB_MEDIUM;
                }
                else if (strncmp (p, "LOG_RNB_MAX", sizeof ("LOG_RNB_MAX") - 1) == 0)
                {
                    p += sizeof ("LOG_RNB_MAX") - 1;
                    bitmask |= LOG_RNB_MAX;
                }
                else if (strncmp (p, "LOG_RNB_COMM", sizeof ("LOG_RNB_COMM") - 1) == 0)
                {
                    p += sizeof ("LOG_RNB_COMM") - 1;
                    bitmask |= LOG_RNB_COMM;
                }
                else if (strncmp (p, "LOG_RNB_REMOTE", sizeof ("LOG_RNB_REMOTE") - 1) == 0)
                {
                    p += sizeof ("LOG_RNB_REMOTE") - 1;
                    bitmask |= LOG_RNB_REMOTE;
                }
                else if (strncmp (p, "LOG_RNB_EVENTS", sizeof ("LOG_RNB_EVENTS") - 1) == 0)
                {
                    p += sizeof ("LOG_RNB_EVENTS") - 1;
                    bitmask |= LOG_RNB_EVENTS;
                }
                else if (strncmp (p, "LOG_RNB_PROC", sizeof ("LOG_RNB_PROC") - 1) == 0)
                {
                    p += sizeof ("LOG_RNB_PROC") - 1;
                    bitmask |= LOG_RNB_PROC;
                }
                else if (strncmp (p, "LOG_RNB_PACKETS", sizeof ("LOG_RNB_PACKETS") - 1) == 0)
                {
                    p += sizeof ("LOG_RNB_PACKETS") - 1;
                    bitmask |= LOG_RNB_PACKETS;
                }
                else if (strncmp (p, "LOG_RNB_ALL", sizeof ("LOG_RNB_ALL") - 1) == 0)
                {
                    p += sizeof ("LOG_RNB_ALL") - 1;
                    bitmask |= LOG_RNB_ALL;
                }
                else if (strncmp (p, "LOG_RNB_DEFAULT", sizeof ("LOG_RNB_DEFAULT") - 1) == 0)
                {
                    p += sizeof ("LOG_RNB_DEFAULT") - 1;
                    bitmask |= LOG_RNB_DEFAULT;
                }
                else if (strncmp (p, "LOG_RNB_NONE", sizeof ("LOG_RNB_NONE") - 1) == 0)
                {
                    p += sizeof ("LOG_RNB_NONE") - 1;
                    bitmask = 0;
                }
                else
                {
                    /* Unrecognized logging bit; ignore it.  */
                    const char *c = strchr (p, '|');
                    if (c)
                    {
                        p = c;
                    }
                    else
                    {
                        c = strchr (p, ';');
                        if (c)
                        {
                            p = c;
                        }
                        else
                        {
                            // Improperly terminated word; just go to end of str
                            p = strchr (p, '\0');
                        }
                    }
                }
            }
            // Did we get a properly formatted logging bitmask?
            if (p && *p == ';')
            {
                // Enable DNB logging
                DNBLogSetLogCallback(ASLLogCallback, NULL);
                DNBLogSetLogMask (bitmask);
                p++;
            }
        }
        // We're not going to support logging to a file for now.  All logging
        // goes through ASL.
#if 0
        else if (strncmp (p, "mode=", sizeof ("mode=") - 1) == 0)
        {
            p += sizeof ("mode=") - 1;
            if (strncmp (p, "asl;", sizeof ("asl;") - 1) == 0)
            {
                DNBLogToASL ();
                p += sizeof ("asl;") - 1;
            }
            else if (strncmp (p, "file;", sizeof ("file;") - 1) == 0)
            {
                DNBLogToFile ();
                p += sizeof ("file;") - 1;
            }
            else
            {
                // Ignore unknown argument
                const char *c = strchr (p, ';');
                if (c)
                    p = c + 1;
                else
                    p = strchr (p, '\0');
            }
        }
        else if (strncmp (p, "filename=", sizeof ("filename=") - 1) == 0)
        {
            p += sizeof ("filename=") - 1;
            const char *c = strchr (p, ';');
            if (c == NULL)
            {
                c = strchr (p, '\0');
                continue;
            }
            char *fn = (char *) alloca (c - p + 1);
            strncpy (fn, p, c - p);
            fn[c - p] = '\0';

            // A file name of "asl" is special and is another way to indicate
            // that logging should be done via ASL, not by file.
            if (strcmp (fn, "asl") == 0)
            {
                DNBLogToASL ();
            }
            else
            {
                FILE *f = fopen (fn, "w");
                if (f)
                {
                    DNBLogSetLogFile (f);
                    DNBEnableLogging (f, DNBLogGetLogMask ());
                    DNBLogToFile ();
                }
            }
            p = c + 1;
        }
#endif /* #if 0 to enforce ASL logging only.  */
        else
        {
            // Ignore unknown argument
            const char *c = strchr (p, ';');
            if (c)
                p = c + 1;
            else
                p = strchr (p, '\0');
        }
    }

    return rnb_success;
}

rnb_err_t
RNBRemote::HandlePacket_QThreadSuffixSupported (const char *p)
{
    m_thread_suffix_supported = true;
    return SendPacket ("OK");
}

rnb_err_t
RNBRemote::HandlePacket_QStartNoAckMode (const char *p)
{
    // Send the OK packet first so the correct checksum is appended...
    rnb_err_t result = SendPacket ("OK");
    m_noack_mode = true;
    return result;
}


rnb_err_t
RNBRemote::HandlePacket_QSetLogging (const char *p)
{
    p += sizeof ("QSetLogging:") - 1;
    rnb_err_t result = set_logging (p);
    if (result == rnb_success)
        return SendPacket ("OK");
    else
        return SendPacket ("E35");
}

rnb_err_t
RNBRemote::HandlePacket_QSetDisableASLR (const char *p)
{
    extern int g_disable_aslr;
    p += sizeof ("QSetDisableASLR:") - 1;
    switch (*p)
    {
    case '0': g_disable_aslr = 0; break;
    case '1': g_disable_aslr = 1; break;
    default:
        return SendPacket ("E56");
    }
    return SendPacket ("OK");
}

rnb_err_t
RNBRemote::HandlePacket_QSetSTDIO (const char *p)
{
    // Only set stdin/out/err if we don't already have a process
    if (!m_ctx.HasValidProcessID())
    {
        bool success = false;
        // Check the seventh character since the packet will be one of:
        // QSetSTDIN
        // QSetSTDOUT
        // QSetSTDERR
        StringExtractor packet(p);
        packet.SetFilePos (7);
        char ch = packet.GetChar();
        while (packet.GetChar() != ':')
            /* Do nothing. */;
            
        switch (ch)
        {
            case 'I': // STDIN
                packet.GetHexByteString (m_ctx.GetSTDIN());
                success = !m_ctx.GetSTDIN().empty();
                break;

            case 'O': // STDOUT
                packet.GetHexByteString (m_ctx.GetSTDOUT());
                success = !m_ctx.GetSTDOUT().empty();
                break;

            case 'E': // STDERR
                packet.GetHexByteString (m_ctx.GetSTDERR());
                success = !m_ctx.GetSTDERR().empty();
                break;

            default:
                break;
        }
        if (success)
            return SendPacket ("OK");
        return SendPacket ("E57");
    }
    return SendPacket ("E58");
}

rnb_err_t 
RNBRemote::HandlePacket_QSetWorkingDir (const char *p)
{
    // Only set the working directory if we don't already have a process
    if (!m_ctx.HasValidProcessID())
    {
        StringExtractor packet(p += sizeof ("QSetWorkingDir:") - 1);
        if (packet.GetHexByteString (m_ctx.GetWorkingDir()))
        {
            struct stat working_dir_stat;
            if (::stat(m_ctx.GetWorkingDirPath(), &working_dir_stat) == -1)
            {
                m_ctx.GetWorkingDir().clear();
                return SendPacket ("E61");    // Working directory doesn't exist...
            }
            else if ((working_dir_stat.st_mode & S_IFMT) == S_IFDIR)
            {
                return SendPacket ("OK");
            }
            else
            {
                m_ctx.GetWorkingDir().clear();
                return SendPacket ("E62");    // Working directory isn't a directory...
            }
        }
        return SendPacket ("E59");  // Invalid path
    }
    return SendPacket ("E60"); // Already had a process, too late to set working dir
}

rnb_err_t
RNBRemote::HandlePacket_QSyncThreadState (const char *p)
{
    if (!m_ctx.HasValidProcessID())
    {
        // We allow gdb to connect to a server that hasn't started running
        // the target yet.  gdb still wants to ask questions about it and
        // freaks out if it gets an error.  So just return OK here.
        return SendPacket ("OK");
    }

    errno = 0;
    p += strlen("QSyncThreadState:");
    nub_thread_t tid = strtoul (p, NULL, 16);
    if (errno != 0 && tid == 0)
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Invalid thread number in QSyncThreadState packet");
    }
    if (DNBProcessSyncThreadState(m_ctx.ProcessID(), tid))
        return SendPacket("OK");
    else
        return SendPacket ("E61");
}

rnb_err_t
RNBRemote::HandlePacket_QListThreadsInStopReply (const char *p)
{
    // If this packet is received, it allows us to send an extra key/value
    // pair in the stop reply packets where we will list all of the thread IDs
    // separated by commas:
    //
    //  "threads:10a,10b,10c;"
    //
    // This will get included in the stop reply packet as something like:
    //
    //  "T11thread:10a;00:00000000;01:00010203:threads:10a,10b,10c;"
    //
    // This can save two packets on each stop: qfThreadInfo/qsThreadInfo and
    // speed things up a bit.
    //
    // Send the OK packet first so the correct checksum is appended...
    rnb_err_t result = SendPacket ("OK");
    m_list_threads_in_stop_reply = true;
    return result;
}


rnb_err_t
RNBRemote::HandlePacket_QSetMaxPayloadSize (const char *p)
{
    /* The number of characters in a packet payload that gdb is
     prepared to accept.  The packet-start char, packet-end char,
     2 checksum chars and terminating null character are not included
     in this size.  */
    p += sizeof ("QSetMaxPayloadSize:") - 1;
    errno = 0;
    uint32_t size = strtoul (p, NULL, 16);
    if (errno != 0 && size == 0)
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Invalid length in QSetMaxPayloadSize packet");
    }
    m_max_payload_size = size;
    return SendPacket ("OK");
}

rnb_err_t
RNBRemote::HandlePacket_QSetMaxPacketSize (const char *p)
{
    /* This tells us the largest packet that gdb can handle.
     i.e. the size of gdb's packet-reading buffer.
     QSetMaxPayloadSize is preferred because it is less ambiguous.  */
    p += sizeof ("QSetMaxPacketSize:") - 1;
    errno = 0;
    uint32_t size = strtoul (p, NULL, 16);
    if (errno != 0 && size == 0)
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Invalid length in QSetMaxPacketSize packet");
    }
    m_max_payload_size = size - 5;
    return SendPacket ("OK");
}




rnb_err_t
RNBRemote::HandlePacket_QEnvironment (const char *p)
{
    /* This sets the environment for the target program.  The packet is of the form:

     QEnvironment:VARIABLE=VALUE

     */

    DNBLogThreadedIf (LOG_RNB_REMOTE, "%8u RNBRemote::%s Handling QEnvironment: \"%s\"",
                      (uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__, p);

    p += sizeof ("QEnvironment:") - 1;
    RNBContext& ctx = Context();

    ctx.PushEnvironment (p);
    return SendPacket ("OK");
}

rnb_err_t
RNBRemote::HandlePacket_QEnvironmentHexEncoded (const char *p)
{
    /* This sets the environment for the target program.  The packet is of the form:

        QEnvironmentHexEncoded:VARIABLE=VALUE

        The VARIABLE=VALUE part is sent hex-encoded so chracters like '#' with special
        meaning in the remote protocol won't break it.
    */
       
    DNBLogThreadedIf (LOG_RNB_REMOTE, "%8u RNBRemote::%s Handling QEnvironmentHexEncoded: \"%s\"", 
        (uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__, p);

    p += sizeof ("QEnvironmentHexEncoded:") - 1;
        
    std::string arg;
    const char *c;
    c = p;
    while (*c != '\0')
      {
        if (*(c + 1) == '\0')
        {
            return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "non-hex char in arg on 'QEnvironmentHexEncoded' pkt");
        }
        char smallbuf[3];
        smallbuf[0] = *c;
        smallbuf[1] = *(c + 1);
        smallbuf[2] = '\0';
        errno = 0;
        int ch = strtoul (smallbuf, NULL, 16);
        if (errno != 0 && ch == 0)
          {
            return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "non-hex char in arg on 'QEnvironmentHexEncoded' pkt");
          }
        arg.push_back(ch);
        c += 2;
      }

    RNBContext& ctx = Context();
    if (arg.length() > 0)
      ctx.PushEnvironment (arg.c_str());  

    return SendPacket ("OK");
}


rnb_err_t
RNBRemote::HandlePacket_QLaunchArch (const char *p)
{
    p += sizeof ("QLaunchArch:") - 1;
    if (DNBSetArchitecture(p))
        return SendPacket ("OK");
    return SendPacket ("E63");
}

void
append_hex_value (std::ostream& ostrm, const uint8_t* buf, size_t buf_size, bool swap)
{
    int i;
    if (swap)
    {
        for (i = buf_size-1; i >= 0; i--)
            ostrm << RAWHEX8(buf[i]);
    }
    else
    {
        for (i = 0; i < buf_size; i++)
            ostrm << RAWHEX8(buf[i]);
    }
}


void
register_value_in_hex_fixed_width (std::ostream& ostrm,
                                   nub_process_t pid,
                                   nub_thread_t tid,
                                   const register_map_entry_t* reg,
                                   const DNBRegisterValue *reg_value_ptr)
{
    if (reg != NULL)
    {
        DNBRegisterValue reg_value;
        if (reg_value_ptr == NULL)
        {
            if (DNBThreadGetRegisterValueByID (pid, tid, reg->nub_info.set, reg->nub_info.reg, &reg_value))
                reg_value_ptr = &reg_value;
        }
        
        if (reg_value_ptr)
        {
            append_hex_value (ostrm, reg_value_ptr->value.v_uint8, reg->gdb_size, false);
        }
        else
        {
            // If we fail to read a regiser value, check if it has a default
            // fail value. If it does, return this instead in case some of
            // the registers are not available on the current system.
            if (reg->gdb_size > 0)
            {
                if (reg->fail_value != NULL)
                {
                    append_hex_value (ostrm, reg->fail_value, reg->gdb_size, false);
                }
                else
                {
                    std::basic_string<uint8_t> zeros(reg->gdb_size, '\0');
                    append_hex_value (ostrm, zeros.data(), zeros.size(), false);
                }
            }
        }
    }
}


void
gdb_regnum_with_fixed_width_hex_register_value (std::ostream& ostrm,
                                                nub_process_t pid,
                                                nub_thread_t tid,
                                                const register_map_entry_t* reg,
                                                const DNBRegisterValue *reg_value_ptr)
{
    // Output the register number as 'NN:VVVVVVVV;' where NN is a 2 bytes HEX
    // gdb register number, and VVVVVVVV is the correct number of hex bytes
    // as ASCII for the register value.
    if (reg != NULL)
    {
        ostrm << RAWHEX8(reg->gdb_regnum) << ':';
        register_value_in_hex_fixed_width (ostrm, pid, tid, reg, reg_value_ptr);
        ostrm << ';';
    }
}

rnb_err_t
RNBRemote::SendStopReplyPacketForThread (nub_thread_t tid)
{
    const nub_process_t pid = m_ctx.ProcessID();
    if (pid == INVALID_NUB_PROCESS)
        return SendPacket("E50");

    struct DNBThreadStopInfo tid_stop_info;

    /* Fill the remaining space in this packet with as many registers
     as we can stuff in there.  */

    if (DNBThreadGetStopReason (pid, tid, &tid_stop_info))
    {
        const bool did_exec = tid_stop_info.reason == eStopTypeExec;
        if (did_exec)
            RNBRemote::InitializeRegisters(true);

        std::ostringstream ostrm;
        // Output the T packet with the thread
        ostrm << 'T';
        int signum = tid_stop_info.details.signal.signo;
        DNBLogThreadedIf (LOG_RNB_PROC, "%8d %s got signal signo = %u, exc_type = %u", (uint32_t)m_comm.Timer().ElapsedMicroSeconds(true), __FUNCTION__, signum, tid_stop_info.details.exception.type);

        // Translate any mach exceptions to gdb versions, unless they are
        // common exceptions like a breakpoint or a soft signal.
        switch (tid_stop_info.details.exception.type)
        {
            default:                    signum = 0; break;
            case EXC_BREAKPOINT:        signum = SIGTRAP; break;
            case EXC_BAD_ACCESS:        signum = TARGET_EXC_BAD_ACCESS; break;
            case EXC_BAD_INSTRUCTION:   signum = TARGET_EXC_BAD_INSTRUCTION; break;
            case EXC_ARITHMETIC:        signum = TARGET_EXC_ARITHMETIC; break;
            case EXC_EMULATION:         signum = TARGET_EXC_EMULATION; break;
            case EXC_SOFTWARE:
                if (tid_stop_info.details.exception.data_count == 2 &&
                    tid_stop_info.details.exception.data[0] == EXC_SOFT_SIGNAL)
                    signum = tid_stop_info.details.exception.data[1];
                else
                    signum = TARGET_EXC_SOFTWARE;
                break;
        }

        ostrm << RAWHEX8(signum & 0xff);

        ostrm << std::hex << "thread:" << tid << ';';

        const char *thread_name = DNBThreadGetName (pid, tid);
        if (thread_name && thread_name[0])
        {
            size_t thread_name_len = strlen(thread_name);
            
            if (::strcspn (thread_name, "$#+-;:") == thread_name_len)
                ostrm << std::hex << "name:" << thread_name << ';';
            else
            {
                // the thread name contains special chars, send as hex bytes
                ostrm << std::hex << "hexname:";
                uint8_t *u_thread_name = (uint8_t *)thread_name;
                for (int i = 0; i < thread_name_len; i++)
                    ostrm << RAWHEX8(u_thread_name[i]);
                ostrm << ';';
            }
        }

        thread_identifier_info_data_t thread_ident_info;
        if (DNBThreadGetIdentifierInfo (pid, tid, &thread_ident_info))
        {
            if (thread_ident_info.dispatch_qaddr != 0)
                ostrm << std::hex << "qaddr:" << thread_ident_info.dispatch_qaddr << ';';
        }
        
        // If a 'QListThreadsInStopReply' was sent to enable this feature, we
        // will send all thread IDs back in the "threads" key whose value is
        // a listc of hex thread IDs separated by commas:
        //  "threads:10a,10b,10c;"
        // This will save the debugger from having to send a pair of qfThreadInfo
        // and qsThreadInfo packets, but it also might take a lot of room in the
        // stop reply packet, so it must be enabled only on systems where there
        // are no limits on packet lengths.
        
        if (m_list_threads_in_stop_reply)
        {
            const nub_size_t numthreads = DNBProcessGetNumThreads (pid);
            if (numthreads > 0)
            {
                ostrm << std::hex << "threads:";
                for (nub_size_t i = 0; i < numthreads; ++i)
                {
                    nub_thread_t th = DNBProcessGetThreadAtIndex (pid, i);
                    if (i > 0)
                        ostrm << ',';
                    ostrm << std::hex << th;
                }
                ostrm << ';';
            }
        }

        if (g_num_reg_entries == 0)
            InitializeRegisters ();

        if (g_reg_entries != NULL)
        {
            DNBRegisterValue reg_value;
            for (uint32_t reg = 0; reg < g_num_reg_entries; reg++)
            {
                if (g_reg_entries[reg].expedite)
                {
                    if (!DNBThreadGetRegisterValueByID (pid, tid, g_reg_entries[reg].nub_info.set, g_reg_entries[reg].nub_info.reg, &reg_value))
                        continue;

                    gdb_regnum_with_fixed_width_hex_register_value (ostrm, pid, tid, &g_reg_entries[reg], &reg_value);
                }
            }
        }
        
        if (did_exec)
        {
            ostrm << "reason:exec;";
        }
        else if (tid_stop_info.details.exception.type)
        {
            ostrm << "metype:" << std::hex << tid_stop_info.details.exception.type << ";";
            ostrm << "mecount:" << std::hex << tid_stop_info.details.exception.data_count << ";";
            for (int i = 0; i < tid_stop_info.details.exception.data_count; ++i)
                ostrm << "medata:" << std::hex << tid_stop_info.details.exception.data[i] << ";";
        }
        return SendPacket (ostrm.str ());
    }
    return SendPacket("E51");
}

/* '?'
 The stop reply packet - tell gdb what the status of the inferior is.
 Often called the questionmark_packet.  */

rnb_err_t
RNBRemote::HandlePacket_last_signal (const char *unused)
{
    if (!m_ctx.HasValidProcessID())
    {
        // Inferior is not yet specified/running
        return SendPacket ("E02");
    }

    nub_process_t pid = m_ctx.ProcessID();
    nub_state_t pid_state = DNBProcessGetState (pid);

    switch (pid_state)
    {
        case eStateAttaching:
        case eStateLaunching:
        case eStateRunning:
        case eStateStepping:
        case eStateDetached:
            return rnb_success;  // Ignore

        case eStateSuspended:
        case eStateStopped:
        case eStateCrashed:
            {
                nub_thread_t tid = DNBProcessGetCurrentThread (pid);
                // Make sure we set the current thread so g and p packets return
                // the data the gdb will expect.
                SetCurrentThread (tid);

                SendStopReplyPacketForThread (tid);
            }
            break;

        case eStateInvalid:
        case eStateUnloaded:
        case eStateExited:
            {
                char pid_exited_packet[16] = "";
                int pid_status = 0;
                // Process exited with exit status
                if (!DNBProcessGetExitStatus(pid, &pid_status))
                    pid_status = 0;

                if (pid_status)
                {
                    if (WIFEXITED (pid_status))
                        snprintf (pid_exited_packet, sizeof(pid_exited_packet), "W%02x", WEXITSTATUS (pid_status));
                    else if (WIFSIGNALED (pid_status))
                        snprintf (pid_exited_packet, sizeof(pid_exited_packet), "X%02x", WEXITSTATUS (pid_status));
                    else if (WIFSTOPPED (pid_status))
                        snprintf (pid_exited_packet, sizeof(pid_exited_packet), "S%02x", WSTOPSIG (pid_status));
                }

                // If we have an empty exit packet, lets fill one in to be safe.
                if (!pid_exited_packet[0])
                {
                    strncpy (pid_exited_packet, "W00", sizeof(pid_exited_packet)-1);
                    pid_exited_packet[sizeof(pid_exited_packet)-1] = '\0';
                }

                return SendPacket (pid_exited_packet);
            }
            break;
    }
    return rnb_success;
}

rnb_err_t
RNBRemote::HandlePacket_M (const char *p)
{
    if (p == NULL || p[0] == '\0' || strlen (p) < 3)
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Too short M packet");
    }

    char *c;
    p++;
    errno = 0;
    nub_addr_t addr = strtoull (p, &c, 16);
    if (errno != 0 && addr == 0)
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Invalid address in M packet");
    }
    if (*c != ',')
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Comma sep missing in M packet");
    }

    /* Advance 'p' to the length part of the packet.  */
    p += (c - p) + 1;

    errno = 0;
    uint32_t length = strtoul (p, &c, 16);
    if (errno != 0 && length == 0)
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Invalid length in M packet");
    }
    if (length == 0)
    {
        return SendPacket ("OK");
    }

    if (*c != ':')
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Missing colon in M packet");
    }
    /* Advance 'p' to the data part of the packet.  */
    p += (c - p) + 1;

    int datalen = strlen (p);
    if (datalen & 0x1)
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Uneven # of hex chars for data in M packet");
    }
    if (datalen == 0)
    {
        return SendPacket ("OK");
    }

    uint8_t *buf = (uint8_t *) alloca (datalen / 2);
    uint8_t *i = buf;

    while (*p != '\0' && *(p + 1) != '\0')
    {
        char hexbuf[3];
        hexbuf[0] = *p;
        hexbuf[1] = *(p + 1);
        hexbuf[2] = '\0';
        errno = 0;
        uint8_t byte = strtoul (hexbuf, NULL, 16);
        if (errno != 0 && byte == 0)
        {
            return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Invalid hex byte in M packet");
        }
        *i++ = byte;
        p += 2;
    }

    nub_size_t wrote = DNBProcessMemoryWrite (m_ctx.ProcessID(), addr, length, buf);
    if (wrote != length)
        return SendPacket ("E09");
    else
        return SendPacket ("OK");
}


rnb_err_t
RNBRemote::HandlePacket_m (const char *p)
{
    if (p == NULL || p[0] == '\0' || strlen (p) < 3)
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Too short m packet");
    }

    char *c;
    p++;
    errno = 0;
    nub_addr_t addr = strtoull (p, &c, 16);
    if (errno != 0 && addr == 0)
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Invalid address in m packet");
    }
    if (*c != ',')
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Comma sep missing in m packet");
    }

    /* Advance 'p' to the length part of the packet.  */
    p += (c - p) + 1;

    errno = 0;
    uint32_t length = strtoul (p, NULL, 16);
    if (errno != 0 && length == 0)
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Invalid length in m packet");
    }
    if (length == 0)
    {
        return SendPacket ("");
    }

    uint8_t buf[length];
    int bytes_read = DNBProcessMemoryRead (m_ctx.ProcessID(), addr, length, buf);
    if (bytes_read == 0)
    {
        return SendPacket ("E08");
    }

    // "The reply may contain fewer bytes than requested if the server was able
    //  to read only part of the region of memory."
    length = bytes_read;

    std::ostringstream ostrm;
    for (int i = 0; i < length; i++)
        ostrm << RAWHEX8(buf[i]);
    return SendPacket (ostrm.str ());
}

rnb_err_t
RNBRemote::HandlePacket_X (const char *p)
{
    if (p == NULL || p[0] == '\0' || strlen (p) < 3)
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Too short X packet");
    }

    char *c;
    p++;
    errno = 0;
    nub_addr_t addr = strtoull (p, &c, 16);
    if (errno != 0 && addr == 0)
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Invalid address in X packet");
    }
    if (*c != ',')
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Comma sep missing in X packet");
    }

    /* Advance 'p' to the length part of the packet.  */
    p += (c - p) + 1;

    errno = 0;
    int length = strtoul (p, NULL, 16);
    if (errno != 0 && length == 0)
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Invalid length in m packet");
    }

    // I think gdb sends a zero length write request to test whether this
    // packet is accepted.
    if (length == 0)
    {
        return SendPacket ("OK");
    }

    std::vector<uint8_t> data = decode_binary_data (c, -1);
    std::vector<uint8_t>::const_iterator it;
    uint8_t *buf = (uint8_t *) alloca (data.size ());
    uint8_t *i = buf;
    for (it = data.begin (); it != data.end (); ++it)
    {
        *i++ = *it;
    }

    nub_size_t wrote = DNBProcessMemoryWrite (m_ctx.ProcessID(), addr, data.size(), buf);
    if (wrote != data.size ())
        return SendPacket ("E08");
    return SendPacket ("OK");
}

/* 'g' -- read registers
 Get the contents of the registers for the current thread,
 send them to gdb.
 Should the setting of the Hg packet determine which thread's registers
 are returned?  */

rnb_err_t
RNBRemote::HandlePacket_g (const char *p)
{
    std::ostringstream ostrm;
    if (!m_ctx.HasValidProcessID())
    {
        return SendPacket ("E11");
    }

    if (g_num_reg_entries == 0)
        InitializeRegisters ();

    nub_process_t pid = m_ctx.ProcessID ();
    nub_thread_t tid = ExtractThreadIDFromThreadSuffix (p + 1);
    if (tid == INVALID_NUB_THREAD)
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "No thread specified in p packet");

    if (m_use_native_regs)
    {
        // Get the register context size first by calling with NULL buffer
        nub_size_t reg_ctx_size = DNBThreadGetRegisterContext(pid, tid, NULL, 0);
        if (reg_ctx_size)
        {
            // Now allocate enough space for the entire register context
            std::vector<uint8_t> reg_ctx;
            reg_ctx.resize(reg_ctx_size);
            // Now read the register context
            reg_ctx_size = DNBThreadGetRegisterContext(pid, tid, &reg_ctx[0], reg_ctx.size());
            if (reg_ctx_size)
            {
                append_hex_value (ostrm, reg_ctx.data(), reg_ctx.size(), false);
                return SendPacket (ostrm.str ());
            }
        }
    }
    
    for (uint32_t reg = 0; reg < g_num_reg_entries; reg++)
        register_value_in_hex_fixed_width (ostrm, pid, tid, &g_reg_entries[reg], NULL);

    return SendPacket (ostrm.str ());
}

/* 'G XXX...' -- write registers
 How is the thread for these specified, beyond "the current thread"?
 Does gdb actually use the Hg packet to set this?  */

rnb_err_t
RNBRemote::HandlePacket_G (const char *p)
{
    if (!m_ctx.HasValidProcessID())
    {
        return SendPacket ("E11");
    }

    if (g_num_reg_entries == 0)
        InitializeRegisters ();

    StringExtractor packet(p);
    packet.SetFilePos(1); // Skip the 'G'
    
    nub_process_t pid = m_ctx.ProcessID();
    nub_thread_t tid = ExtractThreadIDFromThreadSuffix (p);
    if (tid == INVALID_NUB_THREAD)
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "No thread specified in p packet");

    if (m_use_native_regs)
    {
        // Get the register context size first by calling with NULL buffer
        nub_size_t reg_ctx_size = DNBThreadGetRegisterContext(pid, tid, NULL, 0);
        if (reg_ctx_size)
        {
            // Now allocate enough space for the entire register context
            std::vector<uint8_t> reg_ctx;
            reg_ctx.resize(reg_ctx_size);
            
            const nub_size_t bytes_extracted = packet.GetHexBytes (&reg_ctx[0], reg_ctx.size(), 0xcc);
            if (bytes_extracted == reg_ctx.size())
            {
                // Now write the register context
                reg_ctx_size = DNBThreadSetRegisterContext(pid, tid, reg_ctx.data(), reg_ctx.size());
                if (reg_ctx_size == reg_ctx.size())
                    return SendPacket ("OK");
                else 
                    return SendPacket ("E55");
            }
            else
            {
                DNBLogError("RNBRemote::HandlePacket_G(%s): extracted %llu of %llu bytes, size mismatch\n", p, (uint64_t)bytes_extracted, (uint64_t)reg_ctx_size);
                return SendPacket ("E64");
            }
        }
        else
            return SendPacket ("E65");
    }


    DNBRegisterValue reg_value;
    for (uint32_t reg = 0; reg < g_num_reg_entries; reg++)
    {
        const register_map_entry_t *reg_entry = &g_reg_entries[reg];

        reg_value.info = reg_entry->nub_info;
        if (packet.GetHexBytes (reg_value.value.v_sint8, reg_entry->gdb_size, 0xcc) != reg_entry->gdb_size)
            break;

        if (reg_entry->fail_value == NULL)
        {
            if (!DNBThreadSetRegisterValueByID (pid, tid, reg_entry->nub_info.set, reg_entry->nub_info.reg, &reg_value))
                return SendPacket ("E15");
        }
    }
    return SendPacket ("OK");
}

static bool
RNBRemoteShouldCancelCallback (void *not_used)
{
    RNBRemoteSP remoteSP(g_remoteSP);
    if (remoteSP.get() != NULL)
    {
        RNBRemote* remote = remoteSP.get();
        if (remote->Comm().IsConnected())
            return false;
        else
            return true;
    }
    return true;
}


// FORMAT: _MXXXXXX,PPP   
//      XXXXXX: big endian hex chars
//      PPP: permissions can be any combo of r w x chars
//
// RESPONSE: XXXXXX
//      XXXXXX: hex address of the newly allocated memory
//      EXX: error code
//
// EXAMPLES:
//      _M123000,rw
//      _M123000,rwx
//      _M123000,xw

rnb_err_t
RNBRemote::HandlePacket_AllocateMemory (const char *p)
{
    StringExtractor packet (p);
    packet.SetFilePos(2); // Skip the "_M"
    
    nub_addr_t size = packet.GetHexMaxU64 (StringExtractor::BigEndian, 0);
    if (size != 0)
    {
        if (packet.GetChar() == ',')
        {
            uint32_t permissions = 0;
            char ch;
            bool success = true;
            while (success && (ch = packet.GetChar()) != '\0')
            {
                switch (ch)
                {
                case 'r':   permissions |= eMemoryPermissionsReadable; break;
                case 'w':   permissions |= eMemoryPermissionsWritable; break;
                case 'x':   permissions |= eMemoryPermissionsExecutable; break;
                default:    success = false; break;
                }
            }
            
            if (success)
            {
                nub_addr_t addr = DNBProcessMemoryAllocate (m_ctx.ProcessID(), size, permissions);
                if (addr != INVALID_NUB_ADDRESS)
                {
                    std::ostringstream ostrm;
                    ostrm << RAW_HEXBASE << addr;
                    return SendPacket (ostrm.str ());
                }
            }
        }
    }
    return SendPacket ("E53");
}

// FORMAT: _mXXXXXX   
//      XXXXXX: address that was previosly allocated
//
// RESPONSE: XXXXXX
//      OK: address was deallocated
//      EXX: error code
//
// EXAMPLES: 
//      _m123000

rnb_err_t
RNBRemote::HandlePacket_DeallocateMemory (const char *p)
{
    StringExtractor packet (p);
    packet.SetFilePos(2); // Skip the "_m"
    nub_addr_t addr = packet.GetHexMaxU64 (StringExtractor::BigEndian, INVALID_NUB_ADDRESS);

    if (addr != INVALID_NUB_ADDRESS)
    {
        if (DNBProcessMemoryDeallocate (m_ctx.ProcessID(), addr))
            return SendPacket ("OK");
    }
    return SendPacket ("E54");
}

static bool
GetProcessNameFrom_vAttach (const char *&p, std::string &attach_name)
{
    bool return_val = true;
    while (*p != '\0')
    {
        char smallbuf[3];
        smallbuf[0] = *p;
        smallbuf[1] = *(p + 1);
        smallbuf[2] = '\0';

        errno = 0;
        int ch = strtoul (smallbuf, NULL, 16);
        if (errno != 0 && ch == 0)
        {
            return_val = false;
            break;
        }

        attach_name.push_back(ch);
        p += 2;
    }
    return return_val;
}

/*
 vAttach;pid

 Attach to a new process with the specified process ID. pid is a hexadecimal integer
 identifying the process. If the stub is currently controlling a process, it is
 killed. The attached process is stopped.This packet is only available in extended
 mode (see extended mode).

 Reply:
 "ENN"                      for an error
 "Any Stop Reply Packet"     for success
 */

rnb_err_t
RNBRemote::HandlePacket_v (const char *p)
{
    if (strcmp (p, "vCont;c") == 0)
    {
        // Simple continue
        return RNBRemote::HandlePacket_c("c");
    }
    else if (strcmp (p, "vCont;s") == 0)
    {
        // Simple step
        return RNBRemote::HandlePacket_s("s");
    }
    else if (strstr (p, "vCont") == p)
    {
        typedef struct
        {
            nub_thread_t tid;
            char action;
            int signal;
        } vcont_action_t;

        DNBThreadResumeActions thread_actions;
        char *c = (char *)(p += strlen("vCont"));
        char *c_end = c + strlen(c);
        if (*c == '?')
            return SendPacket ("vCont;c;C;s;S");

        while (c < c_end && *c == ';')
        {
            ++c;    // Skip the semi-colon
            DNBThreadResumeAction thread_action;
            thread_action.tid = INVALID_NUB_THREAD;
            thread_action.state = eStateInvalid;
            thread_action.signal = 0;
            thread_action.addr = INVALID_NUB_ADDRESS;

            char action = *c++;

            switch (action)
            {
                case 'C':
                    errno = 0;
                    thread_action.signal = strtoul (c, &c, 16);
                    if (errno != 0)
                        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Could not parse signal in vCont packet");
                    // Fall through to next case...

                case 'c':
                    // Continue
                    thread_action.state = eStateRunning;
                    break;

                case 'S':
                    errno = 0;
                    thread_action.signal = strtoul (c, &c, 16);
                    if (errno != 0)
                        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Could not parse signal in vCont packet");
                    // Fall through to next case...

                case 's':
                    // Step
                    thread_action.state = eStateStepping;
                    break;

                default:
                    HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Unsupported action in vCont packet");
                    break;
            }
            if (*c == ':')
            {
                errno = 0;
                thread_action.tid = strtoul (++c, &c, 16);
                if (errno != 0)
                    return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Could not parse thread number in vCont packet");
            }

            thread_actions.Append (thread_action);
        }

        // If a default action for all other threads wasn't mentioned
        // then we should stop the threads
        thread_actions.SetDefaultThreadActionIfNeeded (eStateStopped, 0);
        DNBProcessResume(m_ctx.ProcessID(), thread_actions.GetFirst (), thread_actions.GetSize());
        return rnb_success;
    }
    else if (strstr (p, "vAttach") == p)
    {
        nub_process_t attach_pid = INVALID_NUB_PROCESS;
        char err_str[1024]={'\0'};
        
        if (strstr (p, "vAttachWait;") == p)
        {
            p += strlen("vAttachWait;");
            std::string attach_name;
            if (!GetProcessNameFrom_vAttach(p, attach_name))
            {
                return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "non-hex char in arg on 'vAttachWait' pkt");
            }
            const bool ignore_existing = true;
            attach_pid = DNBProcessAttachWait(attach_name.c_str (), m_ctx.LaunchFlavor(), ignore_existing, NULL, 1000, err_str, sizeof(err_str), RNBRemoteShouldCancelCallback);

        }
        else if (strstr (p, "vAttachOrWait;") == p)
        {
            p += strlen("vAttachOrWait;");
            std::string attach_name;
            if (!GetProcessNameFrom_vAttach(p, attach_name))
            {
                return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "non-hex char in arg on 'vAttachOrWait' pkt");
            }
            const bool ignore_existing = false;
            attach_pid = DNBProcessAttachWait(attach_name.c_str (), m_ctx.LaunchFlavor(), ignore_existing, NULL, 1000, err_str, sizeof(err_str), RNBRemoteShouldCancelCallback);
        }
        else if (strstr (p, "vAttachName;") == p)
        {
            p += strlen("vAttachName;");
            std::string attach_name;
            if (!GetProcessNameFrom_vAttach(p, attach_name))
            {
                return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "non-hex char in arg on 'vAttachName' pkt");
            }

            attach_pid = DNBProcessAttachByName (attach_name.c_str(), NULL, err_str, sizeof(err_str));

        }
        else if (strstr (p, "vAttach;") == p)
        {
            p += strlen("vAttach;");
            char *end = NULL;
            attach_pid = strtoul (p, &end, 16);    // PID will be in hex, so use base 16 to decode
            if (p != end && *end == '\0')
            {
                // Wait at most 30 second for attach
                struct timespec attach_timeout_abstime;
                DNBTimer::OffsetTimeOfDay(&attach_timeout_abstime, 30, 0);
                attach_pid = DNBProcessAttach(attach_pid, &attach_timeout_abstime, err_str, sizeof(err_str));
            }
        }
        else
        {
            return HandlePacket_UNIMPLEMENTED(p);
        }


        if (attach_pid != INVALID_NUB_PROCESS)
        {
            if (m_ctx.ProcessID() != attach_pid)
                m_ctx.SetProcessID(attach_pid);
            // Send a stop reply packet to indicate we successfully attached!
            NotifyThatProcessStopped ();
            return rnb_success;
        }
        else
        {
            m_ctx.LaunchStatus().SetError(-1, DNBError::Generic);
            if (err_str[0])
                m_ctx.LaunchStatus().SetErrorString(err_str);
            else
                m_ctx.LaunchStatus().SetErrorString("attach failed");
            return SendPacket ("E01");  // E01 is our magic error value for attach failed.
        }
    }

    // All other failures come through here
    return HandlePacket_UNIMPLEMENTED(p);
}

/* 'T XX' -- status of thread
 Check if the specified thread is alive.
 The thread number is in hex?  */

rnb_err_t
RNBRemote::HandlePacket_T (const char *p)
{
    p++;
    if (p == NULL || *p == '\0')
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "No thread specified in T packet");
    }
    if (!m_ctx.HasValidProcessID())
    {
        return SendPacket ("E15");
    }
    errno = 0;
    nub_thread_t tid = strtoul (p, NULL, 16);
    if (errno != 0 && tid == 0)
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Could not parse thread number in T packet");
    }

    nub_state_t state = DNBThreadGetState (m_ctx.ProcessID(), tid);
    if (state == eStateInvalid || state == eStateExited || state == eStateCrashed)
    {
        return SendPacket ("E16");
    }

    return SendPacket ("OK");
}


rnb_err_t
RNBRemote::HandlePacket_z (const char *p)
{
    if (p == NULL || *p == '\0')
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "No thread specified in z packet");

    if (!m_ctx.HasValidProcessID())
        return SendPacket ("E15");

    char packet_cmd = *p++;
    char break_type = *p++;

    if (*p++ != ',')
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Comma separator missing in z packet");

    char *c = NULL;
    nub_process_t pid = m_ctx.ProcessID();
    errno = 0;
    nub_addr_t addr = strtoull (p, &c, 16);
    if (errno != 0 && addr == 0)
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Invalid address in z packet");
    p = c;
    if (*p++ != ',')
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Comma separator missing in z packet");

    errno = 0;
    uint32_t byte_size = strtoul (p, &c, 16);
    if (errno != 0 && byte_size == 0)
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Invalid length in z packet");

    if (packet_cmd == 'Z')
    {
        // set
        switch (break_type)
        {
            case '0':   // set software breakpoint
            case '1':   // set hardware breakpoint
                {
                    // gdb can send multiple Z packets for the same address and
                    // these calls must be ref counted.
                    bool hardware = (break_type == '1');

                    if (DNBBreakpointSet (pid, addr, byte_size, hardware))
                    {
                        // We successfully created a breakpoint, now lets full out
                        // a ref count structure with the breakID and add it to our
                        // map.
                        return SendPacket ("OK");
                    }
                    else
                    {
                        // We failed to set the software breakpoint
                        return SendPacket ("E09");
                    }
                }
                break;

            case '2':   // set write watchpoint
            case '3':   // set read watchpoint
            case '4':   // set access watchpoint
                {
                    bool hardware = true;
                    uint32_t watch_flags = 0;
                    if (break_type == '2')
                        watch_flags = WATCH_TYPE_WRITE;
                    else if (break_type == '3')
                        watch_flags = WATCH_TYPE_READ;
                    else
                        watch_flags = WATCH_TYPE_READ | WATCH_TYPE_WRITE;

                    if (DNBWatchpointSet (pid, addr, byte_size, watch_flags, hardware))
                    {
                        return SendPacket ("OK");
                    }
                    else
                    {
                        // We failed to set the watchpoint
                        return SendPacket ("E09");
                    }
                }
                break;

            default:
                break;
        }
    }
    else if (packet_cmd == 'z')
    {
        // remove
        switch (break_type)
        {
            case '0':   // remove software breakpoint
            case '1':   // remove hardware breakpoint
                if (DNBBreakpointClear (pid, addr))
                {
                    return SendPacket ("OK");
                }
                else
                {
                    return SendPacket ("E08");
                }
                break;

            case '2':   // remove write watchpoint
            case '3':   // remove read watchpoint
            case '4':   // remove access watchpoint
                if (DNBWatchpointClear (pid, addr))
                {
                    return SendPacket ("OK");
                }
                else
                {
                    return SendPacket ("E08");
                }
                break;

            default:
                break;
        }
    }
    return HandlePacket_UNIMPLEMENTED(p);
}

// Extract the thread number from the thread suffix that might be appended to
// thread specific packets. This will only be enabled if m_thread_suffix_supported
// is true.
nub_thread_t
RNBRemote::ExtractThreadIDFromThreadSuffix (const char *p)
{
    if (m_thread_suffix_supported)
    {
        nub_thread_t tid = INVALID_NUB_THREAD;
        if (p)
        {
            const char *tid_cstr = strstr (p, "thread:");
            if (tid_cstr)
            {
                tid_cstr += strlen ("thread:");
                tid = strtoul(tid_cstr, NULL, 16);
            }
        }
        return tid;
    }
    return GetCurrentThread();

}

/* 'p XX'
 print the contents of register X */

rnb_err_t
RNBRemote::HandlePacket_p (const char *p)
{
    if (g_num_reg_entries == 0)
        InitializeRegisters ();

    if (p == NULL || *p == '\0')
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "No thread specified in p packet");
    }
    if (!m_ctx.HasValidProcessID())
    {
        return SendPacket ("E15");
    }
    nub_process_t pid = m_ctx.ProcessID();
    errno = 0;
    char *tid_cstr = NULL;
    uint32_t reg = strtoul (p + 1, &tid_cstr, 16);
    if (errno != 0 && reg == 0)
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Could not parse register number in p packet");
    }

    nub_thread_t tid = ExtractThreadIDFromThreadSuffix (tid_cstr);
    if (tid == INVALID_NUB_THREAD)
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "No thread specified in p packet");

    const register_map_entry_t *reg_entry;

    if (reg < g_num_reg_entries)
        reg_entry = &g_reg_entries[reg];
    else
        reg_entry = NULL;

    std::ostringstream ostrm;
    if (reg_entry == NULL)
    {
        DNBLogError("RNBRemote::HandlePacket_p(%s): unknown register number %u requested\n", p, reg);
        ostrm << "00000000";
    }
    else if (reg_entry->nub_info.reg == -1)
    {
        if (reg_entry->gdb_size > 0)
        {
            if (reg_entry->fail_value != NULL)
            {
                append_hex_value(ostrm, reg_entry->fail_value, reg_entry->gdb_size, false);
            }
            else
            {
                std::basic_string<uint8_t> zeros(reg_entry->gdb_size, '\0');
                append_hex_value(ostrm, zeros.data(), zeros.size(), false);
            }
        }
    }
    else
    {
        register_value_in_hex_fixed_width (ostrm, pid, tid, reg_entry, NULL);
    }
    return SendPacket (ostrm.str());
}

/* 'Pnn=rrrrr'
 Set register number n to value r.
 n and r are hex strings.  */

rnb_err_t
RNBRemote::HandlePacket_P (const char *p)
{
    if (g_num_reg_entries == 0)
        InitializeRegisters ();

    if (p == NULL || *p == '\0')
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Empty P packet");
    }
    if (!m_ctx.HasValidProcessID())
    {
        return SendPacket ("E28");
    }

    nub_process_t pid = m_ctx.ProcessID();

    StringExtractor packet (p);

    const char cmd_char = packet.GetChar();
    // Register ID is always in big endian
    const uint32_t reg = packet.GetHexMaxU32 (false, UINT32_MAX);
    const char equal_char = packet.GetChar();

    if (cmd_char != 'P')
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Improperly formed P packet");

    if (reg == UINT32_MAX)
        return SendPacket ("E29");

    if (equal_char != '=')
        return SendPacket ("E30");

    const register_map_entry_t *reg_entry;

    if (reg >= g_num_reg_entries)
        return SendPacket("E47");

    reg_entry = &g_reg_entries[reg];

    if (reg_entry->nub_info.set == -1 && reg_entry->nub_info.reg == -1)
    {
        DNBLogError("RNBRemote::HandlePacket_P(%s): unknown register number %u requested\n", p, reg);
        return SendPacket("E48");
    }

    DNBRegisterValue reg_value;
    reg_value.info = reg_entry->nub_info;
    packet.GetHexBytes (reg_value.value.v_sint8, reg_entry->gdb_size, 0xcc);

    nub_thread_t tid = ExtractThreadIDFromThreadSuffix (p);
    if (tid == INVALID_NUB_THREAD)
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "No thread specified in p packet");

    if (!DNBThreadSetRegisterValueByID (pid, tid, reg_entry->nub_info.set, reg_entry->nub_info.reg, &reg_value))
    {
        return SendPacket ("E32");
    }
    return SendPacket ("OK");
}

/* 'c [addr]'
 Continue, optionally from a specified address. */

rnb_err_t
RNBRemote::HandlePacket_c (const char *p)
{
    const nub_process_t pid = m_ctx.ProcessID();

    if (pid == INVALID_NUB_PROCESS)
        return SendPacket ("E23");

    DNBThreadResumeAction action = { INVALID_NUB_THREAD, eStateRunning, 0, INVALID_NUB_ADDRESS };

    if (*(p + 1) != '\0')
    {
        action.tid = GetContinueThread();
        errno = 0;
        action.addr = strtoull (p + 1, NULL, 16);
        if (errno != 0 && action.addr == 0)
            return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Could not parse address in c packet");
    }

    DNBThreadResumeActions thread_actions;
    thread_actions.Append(action);
    thread_actions.SetDefaultThreadActionIfNeeded(eStateRunning, 0);
    if (!DNBProcessResume (pid, thread_actions.GetFirst(), thread_actions.GetSize()))
        return SendPacket ("E25");
    // Don't send an "OK" packet; response is the stopped/exited message.
    return rnb_success;
}

rnb_err_t
RNBRemote::HandlePacket_MemoryRegionInfo (const char *p)
{
    /* This packet will find memory attributes (e.g. readable, writable, executable, stack, jitted code)
       for the memory region containing a given address and return that information.
       
       Users of this packet must be prepared for three results:  

           Region information is returned
           Region information is unavailable for this address because the address is in unmapped memory
           Region lookup cannot be performed on this platform or process is not yet launched
           This packet isn't implemented 

       Examples of use:
          qMemoryRegionInfo:3a55140
          start:3a50000,size:100000,permissions:rwx

          qMemoryRegionInfo:0
          error:address in unmapped region

          qMemoryRegionInfo:3a551140   (on a different platform)
          error:region lookup cannot be performed

          qMemoryRegionInfo
          OK                   // this packet is implemented by the remote nub
    */

    p += sizeof ("qMemoryRegionInfo") - 1;
    if (*p == '\0')
       return SendPacket ("OK");
    if (*p++ != ':')
       return SendPacket ("E67");
    if (*p == '0' && (*(p + 1) == 'x' || *(p + 1) == 'X'))
       p += 2;

    errno = 0;
    uint64_t address = strtoul (p, NULL, 16);
    if (errno != 0 && address == 0)
    {
        return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Invalid address in qMemoryRegionInfo packet");
    }

    DNBRegionInfo region_info = { 0, 0, 0 };
    DNBProcessMemoryRegionInfo (m_ctx.ProcessID(), address, &region_info);
    std::ostringstream ostrm;

        // start:3a50000,size:100000,permissions:rwx
    ostrm << "start:" << std::hex << region_info.addr << ';';

    if (region_info.size > 0)
        ostrm << "size:"  << std::hex << region_info.size << ';';
        
    if (region_info.permissions)
    {
        ostrm << "permissions:";
        
        if (region_info.permissions & eMemoryPermissionsReadable)
            ostrm << 'r';
        if (region_info.permissions & eMemoryPermissionsWritable)
            ostrm << 'w';
        if (region_info.permissions & eMemoryPermissionsExecutable)
            ostrm << 'x';
        ostrm << ';';
    }
    return SendPacket (ostrm.str());
}

// qGetProfileData;scan_type:0xYYYYYYY
rnb_err_t
RNBRemote::HandlePacket_GetProfileData (const char *p)
{
    nub_process_t pid = m_ctx.ProcessID();
    if (pid == INVALID_NUB_PROCESS)
        return SendPacket ("OK");
    
    StringExtractor packet(p += sizeof ("qGetProfileData"));
    DNBProfileDataScanType scan_type = eProfileAll;
    std::string name;
    std::string value;
    while (packet.GetNameColonValue(name, value))
    {
        if (name.compare ("scan_type") == 0)
        {
            std::istringstream iss(value);
            uint32_t int_value = 0;
            if (iss >> std::hex >> int_value)
            {
                scan_type = (DNBProfileDataScanType)int_value;
            }
        }
    }
    
    std::string data = DNBProcessGetProfileData(pid, scan_type);
    if (!data.empty())
    {
        return SendPacket (data.c_str());
    }
    else
    {
        return SendPacket ("OK");
    }
}

// QSetEnableAsyncProfiling;enable:[0|1]:interval_usec:XXXXXX;scan_type:0xYYYYYYY
rnb_err_t
RNBRemote::HandlePacket_SetEnableAsyncProfiling (const char *p)
{
    nub_process_t pid = m_ctx.ProcessID();
    if (pid == INVALID_NUB_PROCESS)
        return SendPacket ("OK");

    StringExtractor packet(p += sizeof ("QSetEnableAsyncProfiling"));
    bool enable = false;
    uint64_t interval_usec = 0;
    DNBProfileDataScanType scan_type = eProfileAll;
    std::string name;
    std::string value;
    while (packet.GetNameColonValue(name, value))
    {
        if (name.compare ("enable") == 0)
        {
            enable  = strtoul(value.c_str(), NULL, 10) > 0;
        }
        else if (name.compare ("interval_usec") == 0)
        {
            interval_usec  = strtoul(value.c_str(), NULL, 10);
        }
        else if (name.compare ("scan_type") == 0)
        {
            std::istringstream iss(value);
            uint32_t int_value = 0;
            if (iss >> std::hex >> int_value)
            {
                scan_type = (DNBProfileDataScanType)int_value;
            }
        }
    }
    
    if (interval_usec == 0)
    {
        enable = 0;
    }
    
    DNBProcessSetEnableAsyncProfiling(pid, enable, interval_usec, scan_type);
    return SendPacket ("OK");
}

rnb_err_t
RNBRemote::HandlePacket_WatchpointSupportInfo (const char *p)
{
    /* This packet simply returns the number of supported hardware watchpoints.
       
       Examples of use:
          qWatchpointSupportInfo:
          num:4

          qWatchpointSupportInfo
          OK                   // this packet is implemented by the remote nub
    */

    p += sizeof ("qWatchpointSupportInfo") - 1;
    if (*p == '\0')
       return SendPacket ("OK");
    if (*p++ != ':')
       return SendPacket ("E67");

    errno = 0;
    uint32_t num = DNBWatchpointGetNumSupportedHWP (m_ctx.ProcessID());
    std::ostringstream ostrm;

    // size:4
    ostrm << "num:" << std::dec << num << ';';
    return SendPacket (ostrm.str());
}

/* 'C sig [;addr]'
 Resume with signal sig, optionally at address addr.  */

rnb_err_t
RNBRemote::HandlePacket_C (const char *p)
{
    const nub_process_t pid = m_ctx.ProcessID();

    if (pid == INVALID_NUB_PROCESS)
        return SendPacket ("E36");

    DNBThreadResumeAction action = { INVALID_NUB_THREAD, eStateRunning, 0, INVALID_NUB_ADDRESS };
    int process_signo = -1;
    if (*(p + 1) != '\0')
    {
        action.tid = GetContinueThread();
        char *end = NULL;
        errno = 0;
        process_signo = strtoul (p + 1, &end, 16);
        if (errno != 0)
            return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Could not parse signal in C packet");
        else if (*end == ';')
        {
            errno = 0;
            action.addr = strtoull (end + 1, NULL, 16);
            if (errno != 0 && action.addr == 0)
                return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Could not parse address in C packet");
        }
    }

    DNBThreadResumeActions thread_actions;
    thread_actions.Append (action);
    thread_actions.SetDefaultThreadActionIfNeeded (eStateRunning, action.signal);
    if (!DNBProcessSignal(pid, process_signo))
        return SendPacket ("E52");
    if (!DNBProcessResume (pid, thread_actions.GetFirst(), thread_actions.GetSize()))
        return SendPacket ("E38");
    /* Don't send an "OK" packet; response is the stopped/exited message.  */
    return rnb_success;
}

//----------------------------------------------------------------------
// 'D' packet
// Detach from gdb.
//----------------------------------------------------------------------
rnb_err_t
RNBRemote::HandlePacket_D (const char *p)
{
    SendPacket ("OK");
    if (m_ctx.HasValidProcessID())
        DNBProcessDetach(m_ctx.ProcessID());
    return rnb_success;
}

/* 'k'
 Kill the inferior process.  */

rnb_err_t
RNBRemote::HandlePacket_k (const char *p)
{
    DNBLog ("Got a 'k' packet, killing the inferior process.");
    // No response to should be sent to the kill packet
    if (m_ctx.HasValidProcessID())
        DNBProcessKill (m_ctx.ProcessID());
    SendPacket ("W09");
    return rnb_success;
}

rnb_err_t
RNBRemote::HandlePacket_stop_process (const char *p)
{
//#define TEST_EXIT_ON_INTERRUPT // This should only be uncommented to test exiting on interrupt
#if defined(TEST_EXIT_ON_INTERRUPT)
    rnb_err_t err = HandlePacket_k (p);
    m_comm.Disconnect(true);
    return err;
#else
    DNBProcessSignal (m_ctx.ProcessID(), SIGSTOP);
    //DNBProcessSignal (m_ctx.ProcessID(), SIGINT);
    // Do not send any response packet! Wait for the stop reply packet to naturally happen
    return rnb_success;
#endif
}

/* 's'
 Step the inferior process.  */

rnb_err_t
RNBRemote::HandlePacket_s (const char *p)
{
    const nub_process_t pid = m_ctx.ProcessID();
    if (pid == INVALID_NUB_PROCESS)
        return SendPacket ("E32");

    // Hardware supported stepping not supported on arm
    nub_thread_t tid = GetContinueThread ();
    if (tid == 0 || tid == -1)
        tid = GetCurrentThread();

    if (tid == INVALID_NUB_THREAD)
        return SendPacket ("E33");

    DNBThreadResumeActions thread_actions;
    thread_actions.AppendAction(tid, eStateStepping);

    // Make all other threads stop when we are stepping
    thread_actions.SetDefaultThreadActionIfNeeded (eStateStopped, 0);
    if (!DNBProcessResume (pid, thread_actions.GetFirst(), thread_actions.GetSize()))
        return SendPacket ("E49");
    // Don't send an "OK" packet; response is the stopped/exited message.
    return rnb_success;
}

/* 'S sig [;addr]'
 Step with signal sig, optionally at address addr.  */

rnb_err_t
RNBRemote::HandlePacket_S (const char *p)
{
    const nub_process_t pid = m_ctx.ProcessID();
    if (pid == INVALID_NUB_PROCESS)
        return SendPacket ("E36");

    DNBThreadResumeAction action = { INVALID_NUB_THREAD, eStateStepping, 0, INVALID_NUB_ADDRESS };

    if (*(p + 1) != '\0')
    {
        char *end = NULL;
        errno = 0;
        action.signal = strtoul (p + 1, &end, 16);
        if (errno != 0)
            return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Could not parse signal in S packet");
        else if (*end == ';')
        {
            errno = 0;
            action.addr = strtoull (end + 1, NULL, 16);
            if (errno != 0 && action.addr == 0)
            {
                return HandlePacket_ILLFORMED (__FILE__, __LINE__, p, "Could not parse address in S packet");
            }
        }
    }

    action.tid = GetContinueThread ();
    if (action.tid == 0 || action.tid == -1)
        return SendPacket ("E40");

    nub_state_t tstate = DNBThreadGetState (pid, action.tid);
    if (tstate == eStateInvalid || tstate == eStateExited)
        return SendPacket ("E37");


    DNBThreadResumeActions thread_actions;
    thread_actions.Append (action);

    // Make all other threads stop when we are stepping
    thread_actions.SetDefaultThreadActionIfNeeded(eStateStopped, 0);
    if (!DNBProcessResume (pid, thread_actions.GetFirst(), thread_actions.GetSize()))
        return SendPacket ("E39");

    // Don't send an "OK" packet; response is the stopped/exited message.
    return rnb_success;
}

rnb_err_t
RNBRemote::HandlePacket_qHostInfo (const char *p)
{
    std::ostringstream strm;

    uint32_t cputype, is_64_bit_capable;
    size_t len = sizeof(cputype);
    bool promoted_to_64 = false;
    if  (::sysctlbyname("hw.cputype", &cputype, &len, NULL, 0) == 0)
    {
        len = sizeof (is_64_bit_capable);
        if  (::sysctlbyname("hw.cpu64bit_capable", &is_64_bit_capable, &len, NULL, 0) == 0)
        {
            if (is_64_bit_capable && ((cputype & CPU_ARCH_ABI64) == 0))
            {
                promoted_to_64 = true;
                cputype |= CPU_ARCH_ABI64;
            }
        }
        
        strm << "cputype:" << std::dec << cputype << ';';
    }

    uint32_t cpusubtype;
    len = sizeof(cpusubtype);
    if (::sysctlbyname("hw.cpusubtype", &cpusubtype, &len, NULL, 0) == 0)
    {
        if (promoted_to_64 && 
            cputype == CPU_TYPE_X86_64 && 
            cpusubtype == CPU_SUBTYPE_486)
            cpusubtype = CPU_SUBTYPE_X86_64_ALL;

        strm << "cpusubtype:" << std::dec << cpusubtype << ';';
    }

    // The OS in the triple should be "ios" or "macosx" which doesn't match our
    // "Darwin" which gets returned from "kern.ostype", so we need to hardcode
    // this for now.
    if (cputype == CPU_TYPE_ARM)
    {
        strm << "ostype:ios;";
        // On armv7 we use "synchronous" watchpoints which means the exception is delivered before the instruction executes.
        strm << "watchpoint_exceptions_received:before;";
    }
    else
    {
        strm << "ostype:macosx;";
        strm << "watchpoint_exceptions_received:after;";
    }
//    char ostype[64];
//    len = sizeof(ostype);
//    if (::sysctlbyname("kern.ostype", &ostype, &len, NULL, 0) == 0)
//    {
//        len = strlen(ostype);
//        std::transform (ostype, ostype + len, ostype, tolower);
//        strm << "ostype:" << std::dec << ostype << ';';
//    }

    strm << "vendor:apple;";

#if defined (__LITTLE_ENDIAN__)
    strm << "endian:little;";
#elif defined (__BIG_ENDIAN__)
    strm << "endian:big;";
#elif defined (__PDP_ENDIAN__)
    strm << "endian:pdp;";
#endif

    if (promoted_to_64)
        strm << "ptrsize:8;";
    else
        strm << "ptrsize:" << std::dec << sizeof(void *) << ';';
    return SendPacket (strm.str());
}


// Note that all numeric values returned by qProcessInfo are hex encoded,
// including the pid and the cpu type.

rnb_err_t
RNBRemote::HandlePacket_qProcessInfo (const char *p)
{
    nub_process_t pid;
    std::ostringstream rep;

    // If we haven't run the process yet, return an error.
    if (!m_ctx.HasValidProcessID())
        return SendPacket ("E68");

    pid = m_ctx.ProcessID();

    rep << "pid:" << std::hex << pid << ";";

    int procpid_mib[4];
    procpid_mib[0] = CTL_KERN;
    procpid_mib[1] = KERN_PROC;
    procpid_mib[2] = KERN_PROC_PID;
    procpid_mib[3] = pid;
    struct kinfo_proc proc_kinfo;
    size_t proc_kinfo_size = sizeof(struct kinfo_proc);

    if (::sysctl (procpid_mib, 4, &proc_kinfo, &proc_kinfo_size, NULL, 0) == 0)
    {
        if (proc_kinfo_size > 0)
        {
            rep << "parent-pid:" << std::hex << proc_kinfo.kp_eproc.e_ppid << ";";
            rep << "real-uid:" << std::hex << proc_kinfo.kp_eproc.e_pcred.p_ruid << ";";
            rep << "real-gid:" << std::hex << proc_kinfo.kp_eproc.e_pcred.p_rgid << ";";
            rep << "effective-uid:" << std::hex << proc_kinfo.kp_eproc.e_ucred.cr_uid << ";";
            if (proc_kinfo.kp_eproc.e_ucred.cr_ngroups > 0)
                rep << "effective-gid:" << std::hex << proc_kinfo.kp_eproc.e_ucred.cr_groups[0] << ";";
        }
    }
    
    cpu_type_t cputype = DNBProcessGetCPUType (pid);
    if (cputype != 0)
    {
        rep << "cputype:" << std::hex << cputype << ";";
    }

    uint32_t cpusubtype;
    size_t cpusubtype_len = sizeof(cpusubtype);
    if (::sysctlbyname("hw.cpusubtype", &cpusubtype, &cpusubtype_len, NULL, 0) == 0)
    {
        if (cputype == CPU_TYPE_X86_64 && cpusubtype == CPU_SUBTYPE_486)
        {
            cpusubtype = CPU_SUBTYPE_X86_64_ALL;
        }

        rep << "cpusubtype:" << std::hex << cpusubtype << ';';
    }

    // The OS in the triple should be "ios" or "macosx" which doesn't match our
    // "Darwin" which gets returned from "kern.ostype", so we need to hardcode
    // this for now.
    if (cputype == CPU_TYPE_ARM)
        rep << "ostype:ios;";
    else
        rep << "ostype:macosx;";

    rep << "vendor:apple;";

#if defined (__LITTLE_ENDIAN__)
    rep << "endian:little;";
#elif defined (__BIG_ENDIAN__)
    rep << "endian:big;";
#elif defined (__PDP_ENDIAN__)
    rep << "endian:pdp;";
#endif

#if (defined (__x86_64__) || defined (__i386__)) && defined (x86_THREAD_STATE)
    nub_thread_t thread = DNBProcessGetCurrentThreadMachPort (pid);
    kern_return_t kr;
    x86_thread_state_t gp_regs;
    mach_msg_type_number_t gp_count = x86_THREAD_STATE_COUNT;
    kr = thread_get_state (thread, x86_THREAD_STATE,
                           (thread_state_t) &gp_regs, &gp_count);
    if (kr == KERN_SUCCESS)
    {
        if (gp_regs.tsh.flavor == x86_THREAD_STATE64)
            rep << "ptrsize:8;";
        else
            rep << "ptrsize:4;";
    }
#elif defined (__arm__)
    rep << "ptrsize:4;";
#endif

    return SendPacket (rep.str());
}


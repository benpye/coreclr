//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information. 
//

/*++



Module Name:

    context.c

Abstract:

    Implementation of GetThreadContext/SetThreadContext/DebugBreak functions for
    the ARM platform. These functions are processor dependent.



--*/

#include "pal/palinternal.h"
#include "pal/dbgmsg.h"
#include "pal/context.h"
#include "pal/debug.h"
#include "pal/thread.hpp"

#include <sys/ptrace.h> 
#include <errno.h>
#include <unistd.h>

SET_DEFAULT_DEBUG_CHANNEL(DEBUG);

// in context2.S
extern void CONTEXT_CaptureContext(LPCONTEXT lpContext);

#if HAVE_BSD_REGS_T
#include <machine/reg.h>
#include <machine/npx.h>
#endif  // HAVE_BSD_REGS_T
#if HAVE_PT_REGS
#include <asm/ptrace.h>
#endif  // HAVE_PT_REGS

#define ASSIGN_CONTROL_REGS \
        ASSIGN_REG(Sp)     \
        ASSIGN_REG(Lr)     \
        ASSIGN_REG(Pc)   \
        ASSIGN_REG(Cpsr)  \

#define ASSIGN_INTEGER_REGS \
        ASSIGN_REG(R0)     \
        ASSIGN_REG(R1)     \
        ASSIGN_REG(R2)     \
        ASSIGN_REG(R3)     \
        ASSIGN_REG(R4)     \
        ASSIGN_REG(R5)     \
        ASSIGN_REG(R6)     \
        ASSIGN_REG(R7)     \
        ASSIGN_REG(R8)     \
        ASSIGN_REG(R9)     \
        ASSIGN_REG(R10)     \
        ASSIGN_REG(R11)     \
        ASSIGN_REG(R12)

#define ASSIGN_ALL_REGS     \
        ASSIGN_CONTROL_REGS \
        ASSIGN_INTEGER_REGS \

/*++
Function:
  CONTEXT_GetRegisters

Abstract
  retrieve the machine registers value of the indicated process.

Parameter
  processId: process ID
  registers: reg structure in which the machine registers value will be returned.
Return
 returns TRUE if it succeeds, FALSE otherwise
--*/
BOOL CONTEXT_GetRegisters(DWORD processId, ucontext_t *registers)
{
#if HAVE_BSD_REGS_T
    int regFd = -1;
#endif  // HAVE_BSD_REGS_T
    BOOL bRet = FALSE;

    if (processId == GetCurrentProcessId()) 
    {
#if HAVE_GETCONTEXT
        if (getcontext(registers) != 0)
        {
            ASSERT("getcontext() failed %d (%s)\n", errno, strerror(errno));
            return FALSE;
        }
#elif HAVE_BSD_REGS_T
        char buf[MAX_PATH];
        struct reg bsd_registers;

        sprintf_s(buf, sizeof(buf), "/proc/%d/regs", processId);

        if ((regFd = PAL__open(buf, O_RDONLY)) == -1) 
        {
          ASSERT("PAL__open() failed %d (%s) \n", errno, strerror(errno));
          return FALSE;
        }

        if (lseek(regFd, 0, 0) == -1)
        {
            ASSERT("lseek() failed %d (%s)\n", errno, strerror(errno));
            goto EXIT;
        }

        if (read(regFd, &bsd_registers, sizeof(bsd_registers)) != sizeof(bsd_registers))
        {
            ASSERT("read() failed %d (%s)\n", errno, strerror(errno));
            goto EXIT;
        }

#define ASSIGN_REG(reg) MCREG_##reg(registers->uc_mcontext) = BSDREG_##reg(bsd_registers);
        ASSIGN_ALL_REGS
#undef ASSIGN_REG

#else
#error "Don't know how to get current context on this platform!"
#endif
    }
    else
    {
#if HAVE_PT_REGS
        struct pt_regs ptrace_registers;
        if (ptrace((__ptrace_request)PT_GETREGS, processId, (caddr_t) &ptrace_registers, 0) == -1)
#elif HAVE_BSD_REGS_T
        struct reg ptrace_registers;
        if (ptrace(PT_GETREGS, processId, (caddr_t) &ptrace_registers, 0) == -1)
#endif
        {
            ASSERT("Failed ptrace(PT_GETREGS, processId:%d) errno:%d (%s)\n",
                   processId, errno, strerror(errno));
        }

#if HAVE_PT_REGS
#define ASSIGN_REG(reg) MCREG_##reg(registers->uc_mcontext) = PTREG_##reg(ptrace_registers);
#elif HAVE_BSD_REGS_T
#define ASSIGN_REG(reg) MCREG_##reg(registers->uc_mcontext) = BSDREG_##reg(ptrace_registers);
#endif
        ASSIGN_ALL_REGS
#undef ASSIGN_REG
    }
    
    bRet = TRUE;
#if HAVE_BSD_REGS_T
EXIT :
    if (regFd != -1)
    {
        close(regFd);
    }
#endif  // HAVE_BSD_REGS_T
    return bRet;
}

/*++
Function:
  GetThreadContext

See MSDN doc.
--*/
BOOL
CONTEXT_GetThreadContext(
         DWORD dwProcessId,
         pthread_t self,
         DWORD dwLwpId,
         LPCONTEXT lpContext)
{    
    BOOL ret = FALSE;
    ucontext_t registers;

    if (lpContext == NULL)
    {
        ERROR("Invalid lpContext parameter value\n");
        SetLastError(ERROR_NOACCESS);
        goto EXIT;
    }
    
    /* How to consider the case when self is different from the current
       thread of its owner process. Machine registers values could be retreived
       by a ptrace(pid, ...) call or from the "/proc/%pid/reg" file content. 
       Unfortunately, these two methods only depend on process ID, not on 
       thread ID. */

    if (dwProcessId == GetCurrentProcessId())
    {
        if (self != pthread_self())
        {
            DWORD flags;
            // There aren't any APIs for this. We can potentially get the
            // context of another thread by using per-thread signals, but
            // on FreeBSD signal handlers that are called as a result
            // of signals raised via pthread_kill don't get a valid
            // sigcontext or ucontext_t. But we need this to return TRUE
            // to avoid an assertion in the CLR in code that manages to
            // cope reasonably well without a valid thread context.
            // Given that, we'll zero out our structure and return TRUE.
            ERROR("GetThreadContext on a thread other than the current "
                  "thread is returning TRUE\n");
            flags = lpContext->ContextFlags;
            memset(lpContext, 0, sizeof(*lpContext));
            lpContext->ContextFlags = flags;
            ret = TRUE;
            goto EXIT;
        }

    }

    if (lpContext->ContextFlags & 
        (CONTEXT_CONTROL | CONTEXT_INTEGER))
    {        
        if (CONTEXT_GetRegisters(dwProcessId, &registers) == FALSE)
        {
            SetLastError(ERROR_INTERNAL_ERROR);
            goto EXIT;
        }

        CONTEXTFromNativeContext(&registers, lpContext, lpContext->ContextFlags);        
    }

    ret = TRUE;

EXIT:
    return ret;
}

/*++
Function:
  SetThreadContext

See MSDN doc.
--*/
BOOL
CONTEXT_SetThreadContext(
           DWORD dwProcessId,
           pthread_t self,
           DWORD dwLwpId,
           CONST CONTEXT *lpContext)
{
    BOOL ret = FALSE;

#if HAVE_PT_REGS
    struct pt_regs ptrace_registers;
#elif HAVE_BSD_REGS_T
    struct reg ptrace_registers;
#endif

    if (lpContext == NULL)
    {
        ERROR("Invalid lpContext parameter value\n");
        SetLastError(ERROR_NOACCESS);
        goto EXIT;
    }
    
    /* How to consider the case when self is different from the current
       thread of its owner process. Machine registers values could be retreived
       by a ptrace(pid, ...) call or from the "/proc/%pid/reg" file content. 
       Unfortunately, these two methods only depend on process ID, not on 
       thread ID. */
        
    if (dwProcessId == GetCurrentProcessId())
    {
#ifdef FEATURE_PAL_SXS
        // Need to implement SetThreadContext(current thread) for the IX architecture; look at common_signal_handler.
        _ASSERT(FALSE);
#endif // FEATURE_PAL_SXS
        ASSERT("SetThreadContext should be called for cross-process only.\n");
        SetLastError(ERROR_INVALID_PARAMETER);
        goto EXIT;
    }
    
    if (lpContext->ContextFlags  & 
        (CONTEXT_CONTROL | CONTEXT_INTEGER))
    {   
#if HAVE_PT_REGS
        if (ptrace((__ptrace_request)PT_GETREGS, dwProcessId, (caddr_t)&ptrace_registers, 0) == -1)
#elif HAVE_BSD_REGS_T
        if (ptrace(PT_GETREGS, dwProcessId, (caddr_t)&ptrace_registers, 0) == -1)
#endif
        {
            ASSERT("Failed ptrace(PT_GETREGS, processId:%d) errno:%d (%s)\n",
                   dwProcessId, errno, strerror(errno));
             SetLastError(ERROR_INTERNAL_ERROR);
             goto EXIT;
        }

#if HAVE_PT_REGS
#define ASSIGN_REG(reg) PTREG_##reg(ptrace_registers) = lpContext->reg;
#elif HAVE_BSD_REGS_T
#define ASSIGN_REG(reg) BSDREG_##reg(ptrace_registers) = lpContext->reg;
#endif
        if (lpContext->ContextFlags & CONTEXT_CONTROL)
        {
            ASSIGN_CONTROL_REGS
        }
        if (lpContext->ContextFlags & CONTEXT_INTEGER)
        {
            ASSIGN_INTEGER_REGS
        }
#undef ASSIGN_REG

#if HAVE_PT_REGS        
        if (ptrace((__ptrace_request)PT_SETREGS, dwProcessId, (caddr_t)&ptrace_registers, 0) == -1)
#elif HAVE_BSD_REGS_T
        if (ptrace(PT_SETREGS, dwProcessId, (caddr_t)&ptrace_registers, 0) == -1)
#endif
        {
            ASSERT("Failed ptrace(PT_SETREGS, processId:%d) errno:%d (%s)\n",
                   dwProcessId, errno, strerror(errno));
            SetLastError(ERROR_INTERNAL_ERROR);
            goto EXIT;
        }
    }

    ret = TRUE;
   EXIT:
     return ret;
}

/*++
Function :
    CONTEXTToNativeContext
    
    Converts a CONTEXT record to a native context.

Parameters :
    CONST CONTEXT *lpContext : CONTEXT to convert
    native_context_t *native : native context to fill in
    ULONG contextFlags : flags that determine which registers are valid in
                         lpContext and which ones to set in native

Return value :
    None

--*/
void CONTEXTToNativeContext(CONST CONTEXT *lpContext, native_context_t *native)
{
#define ASSIGN_REG(reg) MCREG_##reg(native->uc_mcontext) = lpContext->reg;
    if ((lpContext->ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL)
    {
        ASSIGN_CONTROL_REGS
    }

    if ((lpContext->ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER)
    {
        ASSIGN_INTEGER_REGS
    }
#undef ASSIGN_REG

    if ((lpContext->ContextFlags & CONTEXT_FLOATING_POINT) == CONTEXT_FLOATING_POINT)
    {
        // TODO: Implement this     
    }
}

/*++
Function :
    CONTEXTFromNativeContext
    
    Converts a native context to a CONTEXT record.

Parameters :
    const native_context_t *native : native context to convert
    LPCONTEXT lpContext : CONTEXT to fill in
    ULONG contextFlags : flags that determine which registers are valid in
                         native and which ones to set in lpContext

Return value :
    None

--*/
void CONTEXTFromNativeContext(const native_context_t *native, LPCONTEXT lpContext,
                              ULONG contextFlags)
{
    lpContext->ContextFlags = contextFlags;

#define ASSIGN_REG(reg) lpContext->reg = MCREG_##reg(native->uc_mcontext);
    if ((contextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL)
    {
        ASSIGN_CONTROL_REGS
    }

    if ((contextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER)
    {
        ASSIGN_INTEGER_REGS
    }
#undef ASSIGN_REG
    
    if ((contextFlags & CONTEXT_FLOATING_POINT) == CONTEXT_FLOATING_POINT)
    {
        // TODO: Implement this     
    }
}

/*++
Function :
    CONTEXTGetPC
    
    Returns the program counter from the native context.

Parameters :
    const native_context_t *native : native context

Return value :
    The program counter from the native context.

--*/
LPVOID CONTEXTGetPC(const native_context_t *context)
{
    return (LPVOID) MCREG_Pc(context->uc_mcontext);
}

/*++
Function :
    CONTEXTGetExceptionCodeForSignal
    
    Translates signal and context information to a Win32 exception code.

Parameters :
    const siginfo_t *siginfo : signal information from a signal handler
    const native_context_t *context : context information

Return value :
    The Win32 exception code that corresponds to the signal and context
    information.

--*/
#ifdef ILL_ILLOPC
// If si_code values are available for all signals, use those.
DWORD CONTEXTGetExceptionCodeForSignal(const siginfo_t *siginfo,
                                       const native_context_t *context)
{
    switch (siginfo->si_signo)
    {
        case SIGILL:
            switch (siginfo->si_code)
            {
                case ILL_ILLOPC:    // Illegal opcode
                case ILL_ILLOPN:    // Illegal operand
                case ILL_ILLADR:    // Illegal addressing mode
                case ILL_ILLTRP:    // Illegal trap
                case ILL_COPROC:    // Co-processor error
                    return EXCEPTION_ILLEGAL_INSTRUCTION;
                case ILL_PRVOPC:    // Privileged opcode
                case ILL_PRVREG:    // Privileged register
                    return EXCEPTION_PRIV_INSTRUCTION;
                case ILL_BADSTK:    // Internal stack error
                    return EXCEPTION_STACK_OVERFLOW;
                default:
                    break;
            }
            break;
        case SIGFPE:
            switch (siginfo->si_code)
            {
                case FPE_INTDIV:
                    return EXCEPTION_INT_DIVIDE_BY_ZERO;
                case FPE_INTOVF:
                    return EXCEPTION_INT_OVERFLOW;
                case FPE_FLTDIV:
                    return EXCEPTION_FLT_DIVIDE_BY_ZERO;
                case FPE_FLTOVF:
                    return EXCEPTION_FLT_OVERFLOW;
                case FPE_FLTUND:
                    return EXCEPTION_FLT_UNDERFLOW;
                case FPE_FLTRES:
                    return EXCEPTION_FLT_INEXACT_RESULT;
                case FPE_FLTINV:
                    return EXCEPTION_FLT_INVALID_OPERATION;
                case FPE_FLTSUB:
                    return EXCEPTION_FLT_INVALID_OPERATION;
                default:
                    break;
            }
            break;
        case SIGSEGV:
            switch (siginfo->si_code)
            {
                case SI_USER:       // User-generated signal, sometimes sent
                                    // for SIGSEGV under normal circumstances
                case SEGV_MAPERR:   // Address not mapped to object
                case SEGV_ACCERR:   // Invalid permissions for mapped object
                    return EXCEPTION_ACCESS_VIOLATION;
                default:
                    break;
            }
            break;
        case SIGBUS:
            switch (siginfo->si_code)
            {
                case BUS_ADRALN:    // Invalid address alignment
                    return EXCEPTION_DATATYPE_MISALIGNMENT;
                case BUS_ADRERR:    // Non-existent physical address
                    return EXCEPTION_ACCESS_VIOLATION;
                case BUS_OBJERR:    // Object-specific hardware error
                default:
                    break;
            }
        case SIGTRAP:
            switch (siginfo->si_code)
            {
                case SI_KERNEL:
                case SI_USER:
                case TRAP_BRKPT:    // Process breakpoint
                    return EXCEPTION_BREAKPOINT;
                case TRAP_TRACE:    // Process trace trap
                    return EXCEPTION_SINGLE_STEP;
                default:
                    // We don't want to use ASSERT here since it raises SIGTRAP and we
                    // might again end up here resulting in an infinite loop! 
                    // so, we print out an error message and return 
                    DBG_PRINTF(DLI_ASSERT, defdbgchan, TRUE) 
                    ("Got unknown SIGTRAP signal (%d) with code %d\n", SIGTRAP, siginfo->si_code);

                    return EXCEPTION_ILLEGAL_INSTRUCTION;
            }
        default:
            break;
    }
    ASSERT("Got unknown signal number %d with code %d\n",
           siginfo->si_signo, siginfo->si_code);
    return EXCEPTION_ILLEGAL_INSTRUCTION;
}
#else   // ILL_ILLOPC
DWORD CONTEXTGetExceptionCodeForSignal(const siginfo_t *siginfo,
                                       const native_context_t *context)
{
    int trap;

    if (siginfo->si_signo == SIGFPE)
    {
        // Floating point exceptions are mapped by their si_code.
        switch (siginfo->si_code)
        {
            case FPE_INTDIV :
                TRACE("Got signal SIGFPE:FPE_INTDIV; raising "
                      "EXCEPTION_INT_DIVIDE_BY_ZERO\n");
                return EXCEPTION_INT_DIVIDE_BY_ZERO;
                break;
            case FPE_INTOVF :
                TRACE("Got signal SIGFPE:FPE_INTOVF; raising "
                      "EXCEPTION_INT_OVERFLOW\n");
                return EXCEPTION_INT_OVERFLOW;
                break;
            case FPE_FLTDIV :
                TRACE("Got signal SIGFPE:FPE_FLTDIV; raising "
                      "EXCEPTION_FLT_DIVIDE_BY_ZERO\n");
                return EXCEPTION_FLT_DIVIDE_BY_ZERO;
                break;
            case FPE_FLTOVF :
                TRACE("Got signal SIGFPE:FPE_FLTOVF; raising "
                      "EXCEPTION_FLT_OVERFLOW\n");
                return EXCEPTION_FLT_OVERFLOW;
                break;
            case FPE_FLTUND :
                TRACE("Got signal SIGFPE:FPE_FLTUND; raising "
                      "EXCEPTION_FLT_UNDERFLOW\n");
                return EXCEPTION_FLT_UNDERFLOW;
                break;
            case FPE_FLTRES :
                TRACE("Got signal SIGFPE:FPE_FLTRES; raising "
                      "EXCEPTION_FLT_INEXACT_RESULT\n");
                return EXCEPTION_FLT_INEXACT_RESULT;
                break;
            case FPE_FLTINV :
                TRACE("Got signal SIGFPE:FPE_FLTINV; raising "
                      "EXCEPTION_FLT_INVALID_OPERATION\n");
                return EXCEPTION_FLT_INVALID_OPERATION;
                break;
            case FPE_FLTSUB :/* subscript out of range */
                TRACE("Got signal SIGFPE:FPE_FLTSUB; raising "
                      "EXCEPTION_FLT_INVALID_OPERATION\n");
                return EXCEPTION_FLT_INVALID_OPERATION;
                break;
            default:
                ASSERT("Got unknown signal code %d\n", siginfo->si_code);
                break;
        }
    }

    trap = context->uc_mcontext.mc_trapno;
    switch (trap)
    {
        case T_PRIVINFLT : /* privileged instruction */
            TRACE("Trap code T_PRIVINFLT mapped to EXCEPTION_PRIV_INSTRUCTION\n");
            return EXCEPTION_PRIV_INSTRUCTION; 
        case T_BPTFLT :    /* breakpoint instruction */
            TRACE("Trap code T_BPTFLT mapped to EXCEPTION_BREAKPOINT\n");
            return EXCEPTION_BREAKPOINT;
        case T_ARITHTRAP : /* arithmetic trap */
            TRACE("Trap code T_ARITHTRAP maps to floating point exception...\n");
            return 0;      /* let the caller pick an exception code */
#ifdef T_ASTFLT
        case T_ASTFLT :    /* system forced exception : ^C, ^\. SIGINT signal 
                              handler shouldn't be calling this function, since
                              it doesn't need an exception code */
            ASSERT("Trap code T_ASTFLT received, shouldn't get here\n");
            return 0;
#endif  // T_ASTFLT
        case T_PROTFLT :   /* protection fault */
            TRACE("Trap code T_PROTFLT mapped to EXCEPTION_ACCESS_VIOLATION\n");
            return EXCEPTION_ACCESS_VIOLATION; 
        case T_TRCTRAP :   /* debug exception (sic) */
            TRACE("Trap code T_TRCTRAP mapped to EXCEPTION_SINGLE_STEP\n");
            return EXCEPTION_SINGLE_STEP;
        case T_PAGEFLT :   /* page fault */
            TRACE("Trap code T_PAGEFLT mapped to EXCEPTION_ACCESS_VIOLATION\n");
            return EXCEPTION_ACCESS_VIOLATION;
        case T_ALIGNFLT :  /* alignment fault */
            TRACE("Trap code T_ALIGNFLT mapped to EXCEPTION_DATATYPE_MISALIGNMENT\n");
            return EXCEPTION_DATATYPE_MISALIGNMENT;
        case T_DIVIDE :
            TRACE("Trap code T_DIVIDE mapped to EXCEPTION_INT_DIVIDE_BY_ZERO\n");
            return EXCEPTION_INT_DIVIDE_BY_ZERO;
        case T_NMI :       /* non-maskable trap */
            TRACE("Trap code T_NMI mapped to EXCEPTION_ILLEGAL_INSTRUCTION\n");
            return EXCEPTION_ILLEGAL_INSTRUCTION;
        case T_OFLOW :
            TRACE("Trap code T_OFLOW mapped to EXCEPTION_INT_OVERFLOW\n");
            return EXCEPTION_INT_OVERFLOW;
        case T_BOUND :     /* bound instruction fault */
            TRACE("Trap code T_BOUND mapped to EXCEPTION_ARRAY_BOUNDS_EXCEEDED\n");
            return EXCEPTION_ARRAY_BOUNDS_EXCEEDED; 
        case T_DNA :       /* device not available fault */
            TRACE("Trap code T_DNA mapped to EXCEPTION_ILLEGAL_INSTRUCTION\n");
            return EXCEPTION_ILLEGAL_INSTRUCTION; 
        case T_DOUBLEFLT : /* double fault */
            TRACE("Trap code T_DOUBLEFLT mapped to EXCEPTION_ILLEGAL_INSTRUCTION\n");
            return EXCEPTION_ILLEGAL_INSTRUCTION; 
        case T_FPOPFLT :   /* fp coprocessor operand fetch fault */
            TRACE("Trap code T_FPOPFLT mapped to EXCEPTION_FLT_INVALID_OPERATION\n");
            return EXCEPTION_FLT_INVALID_OPERATION; 
        case T_TSSFLT :    /* invalid tss fault */
            TRACE("Trap code T_TSSFLT mapped to EXCEPTION_ILLEGAL_INSTRUCTION\n");
            return EXCEPTION_ILLEGAL_INSTRUCTION; 
        case T_SEGNPFLT :  /* segment not present fault */
            TRACE("Trap code T_SEGNPFLT mapped to EXCEPTION_ACCESS_VIOLATION\n");
            return EXCEPTION_ACCESS_VIOLATION; 
        case T_STKFLT :    /* stack fault */
            TRACE("Trap code T_STKFLT mapped to EXCEPTION_STACK_OVERFLOW\n");
            return EXCEPTION_STACK_OVERFLOW; 
        case T_MCHK :      /* machine check trap */
            TRACE("Trap code T_MCHK mapped to EXCEPTION_ILLEGAL_INSTRUCTION\n");
            return EXCEPTION_ILLEGAL_INSTRUCTION; 
        case T_RESERVED :  /* reserved (unknown) */
            TRACE("Trap code T_RESERVED mapped to EXCEPTION_ILLEGAL_INSTRUCTION\n");
            return EXCEPTION_ILLEGAL_INSTRUCTION; 
        default:
            ASSERT("Got unknown trap code %d\n", trap);
            break;
    }
    return EXCEPTION_ILLEGAL_INSTRUCTION;
}
#endif  // ILL_ILLOPC

/*++
Function:
  DBG_DebugBreak: same as DebugBreak

See MSDN doc.
--*/
VOID
DBG_DebugBreak()
{
    __builtin_trap();
}


/*++
Function:
  DBG_FlushInstructionCache: processor-specific portion of 
  FlushInstructionCache

See MSDN doc.
--*/
BOOL
DBG_FlushInstructionCache(
                          IN LPCVOID lpBaseAddress,
                          IN SIZE_T dwSize)
{
    __clear_cache((LPVOID)lpBaseAddress, (LPVOID)((INT_PTR)lpBaseAddress + dwSize));
    
    return TRUE;
}
// Hack for letting me write code on my laptop
#include <stdbool.h>
#if defined(__aarch64__) || defined(__arm64__)
#define __i386
#endif
#include "lwp.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static schedfun schedule_lwp = round_robin_scheduling; /* default scheduling function is round robin scheduling */
static ptr_int_t *main_thread_sp;                      /* the main thread stack pointer */
static lwp_context *lwp_current = NULL;                /* currently running lwp */
lwp_context lwp_ptable[LWP_PROC_LIMIT];                /* the process table */
int lwp_procs = 0;                                     /* the current number of LWPs */

// Called by the user program.
int new_lwp(lwpfun func, void *arg, size_t size) {
    if (lwp_current != NULL || lwp_procs >= LWP_PROC_LIMIT)
        return -1;

    static int lwp_pid_counter = -1; /* pid counter starts at -1 */

    /* stack initialiation */
    size_t stack_size             = size * WORD_SIZE;                // number of words to allocate for
    ptr_int_t *original_stack_ptr = (ptr_int_t *)malloc(stack_size); // pointer to the lowest address of the memory region for this thread's stack
    ptr_int_t *sp                 = original_stack_ptr + stack_size; // this thread's current stack pointer.

    *(--sp)                  = (ptr_int_t)arg;       // arg
    *(--sp)                  = (ptr_int_t)lwp_exit;  // address func will return to after completing (prob lwp_exit() or lwp_yield())
    *(--sp)                  = (ptr_int_t)func;      // pointer to func
    *(--sp)                  = (ptr_int_t)DUMMY_EBP; // dummy ebp
    ptr_int_t *dummy_ebp_ptr = sp;                   // ptr to dummy ebp

    *--sp = (ptr_int_t)0;             // eax
    *--sp = (ptr_int_t)0;             // ebx
    *--sp = (ptr_int_t)0;             // ecx
    *--sp = (ptr_int_t)0;             // edx
    *--sp = (ptr_int_t)0;             // esi
    *--sp = (ptr_int_t)0;             // edi
    *--sp = (ptr_int_t)dummy_ebp_ptr; // address of dummy ebp

    ++lwp_pid_counter;

    lwp_context context = {
        .pid       = lwp_pid_counter,
        .stack     = original_stack_ptr,
        .sp        = sp,
        .stacksize = stack_size,
        .index     = lwp_procs};

    lwp_ptable[lwp_procs] = context;

    ++lwp_procs;

    return context.pid;
}

// Called by a thread. Returns the pid of the calling LWP. The return value is undefined (-1) if not called by an LWP.
int lwp_getpid() {
    return lwp_current == NULL ? -1 : lwp_current->pid;
}

// Called by a thread. Yields control to another thread. Which thread depends on the scheduler.
// Saves the current thread's context (on its stack), schedules the next thread, restores that thread's context, and returns.
void lwp_yield() {
    if (lwp_current == NULL)
        return;
    // 1. save context on lwp stack
    SAVE_STATE();
    // 2. save new stack pointer
    GetSP(lwp_current->sp);
    // 3. schedule the next thread
    int scheduled_lwp_index   = schedule_lwp();
    lwp_context scheduled_lwp = lwp_ptable[scheduled_lwp_index];
    lwp_current               = &lwp_ptable[scheduled_lwp_index];
    // 4. restore that thread's context
    SetSP(scheduled_lwp.sp);
    RESTORE_STATE();
}

// Called by a thread. Terminates the current LWP, removes it from the process table, and moves all the others up in the table.
// If no threads remain, it should restore the current stack pointer and return to that context.
void lwp_exit() {
    if (lwp_current == NULL)
        return;

    // shift elements downward
    for (int i = lwp_current->index; i < lwp_procs - 1; ++i) {
        lwp_ptable[i] = lwp_ptable[i + 1];
        --lwp_ptable[i].index;
    }

    // decrement number of lwps
    --lwp_procs;

    // if no threads remain (after exiting), restore current stack pointer and return to that context.
    if (lwp_procs == 0) {
        lwp_current = NULL;
        // Todo: Cleanup
        SetSP(main_thread_sp);
        RESTORE_STATE();
    } else {
        int scheduled_lwp_index   = schedule_lwp();
        lwp_context scheduled_lwp = lwp_ptable[scheduled_lwp_index];
        lwp_current               = &lwp_ptable[scheduled_lwp_index];
        SetSP(scheduled_lwp.sp);
        RESTORE_STATE();
    }
}

// Called by the user program. Starts (or resumes) the LWP system.
// Saves the original context and stack pointer (for lwp_stop() or lwp_exit()) to use later, schedules an LWP, and starts it running.
// Returns immediately if there are no LWPs.
void lwp_start() {
    if (lwp_current != NULL)
        return;
    // a. save the "real" context (of the main thread) with SAVE_STATE().
    SAVE_STATE();
    // b. save the "real" stack pointer somewhere where you can find it again.
    GetSP(main_thread_sp);
    // c. schedule one of the lightweight processes to run and switch to its stack.
    int scheduled_lwp_index   = schedule_lwp();
    lwp_context scheduled_lwp = lwp_ptable[scheduled_lwp_index];
    lwp_current               = &lwp_ptable[scheduled_lwp_index];
    // d. load the thread's context with RESTORE_STATE() and you should be off and running.
    SetSP(scheduled_lwp.sp);
    RESTORE_STATE();
}

// Called by a thread. Stops the LWP system, restores the original stack pointer, and returns to that context (wherever lwp_start() was called from).
// lwp_stop() does not destroy any existing contexts, and thread processing will be restarted by a call to lwp_start().
void lwp_stop() {
    if (lwp_current == NULL)
        return;
    // 1. save current lwp's context
    GetSP(lwp_current->sp);
    SAVE_STATE();
    // 2. restore the original stack pointer and return to that context.
    lwp_current = NULL;
    SetSP(main_thread_sp);
    RESTORE_STATE();
}

// Called by the user program. Causes the LWP library to use sched to choose the next LWP to run.
// sched must return an integer in the range [0... lwp_procs - 1]
int round_robin_scheduling(void) {
    static int scheduled_pid = -1;
    if (scheduled_pid + 1 >= lwp_procs)
        scheduled_pid = -1;
    return ++scheduled_pid;
}

void lwp_set_scheduler(schedfun sched) {
    if (sched == NULL)
        schedule_lwp = round_robin_scheduling;
    else
        schedule_lwp = sched;
}

static int get_lwp_context_index(int pid) {
    for (int i = 0; i < lwp_procs; ++i) {
        if (lwp_ptable[i].pid == pid)
            return i;
    }
    // shouldn't be possible
    return -1;
}

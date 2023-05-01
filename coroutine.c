#include "coroutine.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if __APPLE__ && __MACH__
#include <sys/ucontext.h>
#else
#include <ucontext.h>
#endif

#define STACK_SIZE (1024 * 1024)
#define DEFAULT_COROUTINE 16

struct coroutine;

struct schedule {
    char stack[STACK_SIZE];
    ucontext_t main;
    int nco;                // used coroutine size
    int cap;                // maximum coroutine capacity
    int running;            // the index of the running coroutine
    struct coroutine** co;  // coroutine array that can expand dynamically
};

struct coroutine {
    coroutine_func func;
    void* ud;  // parameter
    ucontext_t ctx;
    struct schedule* sch;
    ptrdiff_t cap;   // the capacity of the coroutine's stack
    ptrdiff_t size;  // the used size of the coroutine's stack
    int status;      // enum value: COROUTINE_READY / COROUTINE_RUNNING / COROUTINE_SUSPEND
    char* stack;     // the stack of the coroutine
};

// Create a coroutine
struct coroutine* _co_new(struct schedule* S, coroutine_func func, void* ud) {
    struct coroutine* co = malloc(sizeof(*co));
    co->func = func;
    co->ud = ud;
    co->sch = S;
    co->cap = 0;
    co->size = 0;
    co->status = COROUTINE_READY;
    co->stack = NULL;
    return co;
}

void _co_delete(struct coroutine* co) {
    free(co->stack);
    free(co);
}

struct schedule* coroutine_open(void) {
    struct schedule* S = malloc(sizeof(*S));
    S->nco = 0;
    S->cap = DEFAULT_COROUTINE;
    S->running = -1;
    S->co = malloc(sizeof(struct coroutine*) * S->cap);
    memset(S->co, 0, sizeof(struct coroutine*) * S->cap);
    return S;
}

void coroutine_close(struct schedule* S) {
    int i;
    for (i = 0; i < S->cap; i++) {
        struct coroutine* co = S->co[i];
        if (co) {
            _co_delete(co);
        }
    }
    free(S->co);
    S->co = NULL;
    free(S);
}

int  // return index of the new coroutine in slots
coroutine_new(struct schedule* S, coroutine_func func, void* ud) {
    struct coroutine* co = _co_new(S, func, ud);
    if (S->nco >= S->cap) {  // Expand space if it's full
        int id = S->cap;
        S->co = realloc(S->co, S->cap * 2 * sizeof(struct coroutine*));  // double
        memset(S->co + S->cap, 0, sizeof(struct coroutine*) * S->cap);
        S->co[S->cap] = co;
        S->cap *= 2;
        ++S->nco;
        return id;
    } else {
        int i;
        for (i = 0; i < S->cap; i++) {
            int id = (i + S->nco) % S->cap;
            if (S->co[id] == NULL) {
                S->co[id] = co;
                ++S->nco;
                return id;
            }
        }
    }
    assert(0);  // impossible to arrive it
    return -1;
}

static void mainfunc(uint32_t low32, uint32_t hi32) {
    // initialize
    uintptr_t ptr = (uintptr_t)low32 | ((uintptr_t)hi32 << 32);
    struct schedule* S = (struct schedule*)ptr;
    int id = S->running;
    struct coroutine* C = S->co[id];

    // run
    C->func(S, C->ud);

    // delete coroutine and reset status
    _co_delete(C);
    S->co[id] = NULL;
    --S->nco;
    S->running = -1;
}

void coroutine_resume(struct schedule* S, int id) {
    assert(S->running == -1);
    assert(id >= 0 && id < S->cap);
    struct coroutine* C = S->co[id];
    if (C == NULL) return;
    int status = C->status;
    switch (status) {
        case COROUTINE_READY:  // the first time to run
            getcontext(&C->ctx);
            C->ctx.uc_stack.ss_sp = S->stack;  // specify the stack address of the coroutine
            C->ctx.uc_stack.ss_size = STACK_SIZE;
            C->ctx.uc_link = &S->main;
            S->running = id;
            C->status = COROUTINE_RUNNING;
            uintptr_t ptr = (uintptr_t)S;
            makecontext(&C->ctx, (void (*)(void))mainfunc, 2, (uint32_t)ptr,
                        (uint32_t)(ptr >> 32));  // transfer schedule pointer by lower 32 bits and high 32 bits
            swapcontext(&S->main,
                        &C->ctx);  // save the current context in S->main and switch to the context from C->ctx
            break;
        case COROUTINE_SUSPEND:                                          // not the first time to run
            memcpy(S->stack + STACK_SIZE - C->size, C->stack, C->size);  // resume the stack of the coroutine
            S->running = id;
            C->status = COROUTINE_RUNNING;
            swapcontext(&S->main, &C->ctx);
            break;
        default:
            assert(0);  // impossible
    }
}

static void _save_stack(struct coroutine* C, char* top) {
    char dummy = 0;
    assert(top - &dummy <= STACK_SIZE);  // make sure that the size of the current context is less than the limit
    // store the current stack of the coroutine
    if (C->cap < top - &dummy) {
        free(C->stack);
        C->cap = top - &dummy;
        C->stack = malloc(C->cap);
    }
    C->size = top - &dummy;
    memcpy(C->stack, &dummy, C->size);
}

void coroutine_yield(struct schedule* S) {
    int id = S->running;
    assert(id >= 0);
    struct coroutine* C = S->co[id];
    assert((char*)&C > S->stack);
    _save_stack(C, S->stack + STACK_SIZE);
    C->status = COROUTINE_SUSPEND;
    S->running = -1;
    swapcontext(&C->ctx, &S->main);
}

int coroutine_status(struct schedule* S, int id) {
    assert(id >= 0 && id < S->cap);
    if (S->co[id] == NULL) {
        return COROUTINE_DEAD;
    }
    return S->co[id]->status;
}

int  // return the index of the current running coroutine
coroutine_running(struct schedule* S) {
    return S->running;
}

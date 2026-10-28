/* Reproduce the stale ASan stack shadow without FreeSWITCH or mod_amqp.
 * cc -fPIC -shared -DREPRO_DSO asan_thread_exit_repro.c -lpthread -o libexit.so
 * cc -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined asan_thread_exit_repro.c -L. -lexit -Wl,-rpath,. -lpthread -o bad
 * cc -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -DREPRO_NORETURN asan_thread_exit_repro.c -L. -lexit -Wl,-rpath,. -lpthread -o good
 * GCC 12/libasan: bad fails in sigaltstack at thread exit; good passes.
 */
#include <pthread.h>
#include <stdlib.h>
#ifdef REPRO_DSO
void indirect_exit(void) { pthread_exit(NULL); }
#else
#ifdef REPRO_NORETURN
extern void indirect_exit(void) __attribute__((noreturn));
#else
extern void indirect_exit(void);
#endif
static void *worker(void *data)
{
    volatile char buffer[24];
    buffer[0] = 1;
    buffer[23] = 2;
    if (data) abort();
    indirect_exit();
    return NULL;
}
int main(void)
{
    int i;
    for (i = 0; i < 100; i++) {
        pthread_t thread;
        if (pthread_create(&thread, NULL, worker, NULL)) return 1;
        if (pthread_join(thread, NULL)) return 2;
    }
    return 0;
}
#endif

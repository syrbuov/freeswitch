#include <switch.h>
#include <dlfcn.h>
#include <pthread.h>
#include <string.h>

static pthread_mutex_t gate_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_cond = PTHREAD_COND_INITIALIZER;
static int armed;
static int entered;
static int released;

void amqp_probe_arm_unbind(void)
{
    pthread_mutex_lock(&gate_mutex);
    armed = 1;
    entered = 0;
    released = 0;
    pthread_mutex_unlock(&gate_mutex);
}

int amqp_probe_unbind_entered(void)
{
    int value;
    pthread_mutex_lock(&gate_mutex);
    value = entered;
    pthread_mutex_unlock(&gate_mutex);
    return value;
}

void amqp_probe_release_unbind(void)
{
    pthread_mutex_lock(&gate_mutex);
    released = 1;
    pthread_cond_broadcast(&gate_cond);
    pthread_mutex_unlock(&gate_mutex);
}

SWITCH_DECLARE(switch_status_t) switch_event_unbind(switch_event_node_t **node)
{
    void *symbol = dlsym(RTLD_NEXT, "switch_event_unbind");
    switch_status_t (*next_unbind)(switch_event_node_t **);
    if (!symbol) return SWITCH_STATUS_GENERR;
    memcpy(&next_unbind, &symbol, sizeof(next_unbind));

    pthread_mutex_lock(&gate_mutex);
    if (armed) {
        armed = 0;
        entered = 1;
        pthread_cond_broadcast(&gate_cond);
        while (!released) pthread_cond_wait(&gate_cond, &gate_mutex);
    }
    pthread_mutex_unlock(&gate_mutex);
    return next_unbind(node);
}

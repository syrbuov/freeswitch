/* Test-only accounting around real Core workers/pools; never loaded in service. */
#define _GNU_SOURCE
#include <switch.h>
#include <dlfcn.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct { switch_thread_t *thread; switch_memory_pool_t *pool; int joined; } workers[256];
static int created, joined, early_free, bindings, removed;
static switch_event_node_t *owned_nodes[256];
static int gate, entered, released;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

static void get_symbol(void *out, size_t size, const char *name)
{
    void *symbol = dlsym(RTLD_NEXT, name);
    if (!symbol || size != sizeof(symbol)) abort();
    memcpy(out, &symbol, size);
}

void amqp_probe_counts(int *c, int *j, int *e, int *b, int *r)
{
    pthread_mutex_lock(&lock);
    *c=created; *j=joined; *e=early_free; *b=bindings; *r=removed;
    pthread_mutex_unlock(&lock);
}
void amqp_probe_arm(void) { pthread_mutex_lock(&lock); gate=1; entered=released=0; pthread_mutex_unlock(&lock); }
int amqp_probe_entered(void) { int n; pthread_mutex_lock(&lock); n=entered; pthread_mutex_unlock(&lock); return n; }
void amqp_probe_release(void) { pthread_mutex_lock(&lock); released=1; pthread_cond_broadcast(&cond); pthread_mutex_unlock(&lock); }

SWITCH_DECLARE(switch_status_t) switch_thread_create(switch_thread_t **thread, switch_threadattr_t *attr,
    switch_thread_start_t start, void *data, switch_memory_pool_t *pool)
{
    switch_status_t (*next)(switch_thread_t **, switch_threadattr_t *, switch_thread_start_t, void *, switch_memory_pool_t *);
    switch_status_t result;
    Dl_info info;
    void *address = NULL;
    memcpy(&address, &start, sizeof(address));
    get_symbol(&next, sizeof(next), "switch_thread_create");
    result=next(thread, attr, start, data, pool);
    if (result==SWITCH_STATUS_SUCCESS && dladdr(address, &info) && strstr(info.dli_fname, "/mod_amqp.so")) {
        pthread_mutex_lock(&lock);
        if (created==256) abort();
        workers[created].thread=*thread; workers[created].pool=pool; created++;
        pthread_mutex_unlock(&lock);
    }
    return result;
}
SWITCH_DECLARE(switch_status_t) switch_thread_join(switch_status_t *status, switch_thread_t *thread)
{
    switch_status_t (*next)(switch_status_t *, switch_thread_t *);
    switch_status_t result;
    int i;
    get_symbol(&next, sizeof(next), "switch_thread_join");
    result=next(status, thread);
    if (result==SWITCH_STATUS_SUCCESS) {
        pthread_mutex_lock(&lock);
        for(i=created-1;i>=0;i--) if(workers[i].thread==thread && !workers[i].joined) { workers[i].joined=1; joined++; break; }
        pthread_mutex_unlock(&lock);
    }
    return result;
}
SWITCH_DECLARE(switch_status_t) switch_core_perform_destroy_memory_pool(switch_memory_pool_t **pool,
    const char *file, const char *function, int line)
{
    switch_status_t (*next)(switch_memory_pool_t **, const char *, const char *, int);
    int i;
    get_symbol(&next, sizeof(next), "switch_core_perform_destroy_memory_pool");
    pthread_mutex_lock(&lock);
    for(i=0;i<created;i++) if(workers[i].pool==*pool && !workers[i].joined) early_free++;
    pthread_mutex_unlock(&lock);
    return next(pool,file,function,line);
}
SWITCH_DECLARE(switch_status_t) switch_event_bind_removable(const char *id, switch_event_types_t event, const char *subclass,
    switch_event_callback_t callback, void *data, switch_event_node_t **node)
{
    switch_status_t (*next)(const char *, switch_event_types_t, const char *, switch_event_callback_t, void *, switch_event_node_t **);
    switch_status_t result;
    get_symbol(&next, sizeof(next), "switch_event_bind_removable");
    result=next(id,event,subclass,callback,data,node);
    if(result==SWITCH_STATUS_SUCCESS && id && !strcmp(id,"AMQP")) {
        pthread_mutex_lock(&lock);
        if(bindings==256) abort();
        owned_nodes[bindings++]=*node;
        pthread_mutex_unlock(&lock);
    }
    return result;
}
SWITCH_DECLARE(switch_status_t) switch_event_unbind(switch_event_node_t **node)
{
    switch_status_t (*next)(switch_event_node_t **);
    switch_status_t result;
    int owned=0,i;
    get_symbol(&next, sizeof(next), "switch_event_unbind");
    pthread_mutex_lock(&lock);
    for(i=0;i<bindings;i++) if(node && *node && owned_nodes[i]==*node) { owned=1; owned_nodes[i]=NULL; break; }
    if(owned && gate) { gate=0; entered=1; pthread_cond_broadcast(&cond); while(!released) pthread_cond_wait(&cond,&lock); }
    pthread_mutex_unlock(&lock);
    result=next(node);
    if(owned && result==SWITCH_STATUS_SUCCESS) { pthread_mutex_lock(&lock); removed++; pthread_mutex_unlock(&lock); }
    return result;
}

#include <amqp.h>
static int publishes, in_publish;
void amqp_probe_send_counts(int *started, int *active)
{
    pthread_mutex_lock(&lock); *started=publishes; *active=in_publish; pthread_mutex_unlock(&lock);
}
int amqp_basic_publish(amqp_connection_state_t state, amqp_channel_t channel, amqp_bytes_t exchange, amqp_bytes_t routing_key,
    amqp_boolean_t mandatory, amqp_boolean_t immediate, const amqp_basic_properties_t *properties, amqp_bytes_t body)
{
    int (*next)(amqp_connection_state_t,amqp_channel_t,amqp_bytes_t,amqp_bytes_t,amqp_boolean_t,amqp_boolean_t,const amqp_basic_properties_t *,amqp_bytes_t);
    int result;
    get_symbol(&next,sizeof(next),"amqp_basic_publish");
    pthread_mutex_lock(&lock); publishes++; in_publish++; pthread_mutex_unlock(&lock);
    result=next(state,channel,exchange,routing_key,mandatory,immediate,properties,body);
    if(result < 0) fprintf(stderr,"probe: publish result=%d bytes=%zu\n",result,body.len);
    pthread_mutex_lock(&lock); in_publish--; pthread_mutex_unlock(&lock);
    return result;
}

/* Observe the unchanged legacy console executor while forwarding to real Core.
 * Synthetic commands use no live channel or reachable originate endpoint. */
static int command_calls, command_completed, command_errors;
void amqp_probe_command_counts(int *calls, int *completed, int *errors)
{
    pthread_mutex_lock(&lock);
    *calls=command_calls; *completed=command_completed; *errors=command_errors;
    pthread_mutex_unlock(&lock);
}
SWITCH_DECLARE(switch_status_t) switch_console_execute(char *cmd, int rec, switch_stream_handle_t *stream)
{
    switch_status_t (*next)(char *, int, switch_stream_handle_t *);
    switch_status_t result;
    int exists=!strcmp(cmd,"uuid_exists mod-amqp-local-test-missing-channel");
    int originate=!strcmp(cmd,"bgapi originate error/mod-amqp-local-test &park()");
    get_symbol(&next,sizeof(next),"switch_console_execute");
    if(exists || originate) { pthread_mutex_lock(&lock); command_calls++; pthread_mutex_unlock(&lock); }
    result=next(cmd,rec,stream);
    if(exists || originate) {
        int ok=result==SWITCH_STATUS_SUCCESS && stream->data &&
            (exists?!strcmp(stream->data,"false"):!strncmp(stream->data,"+OK Job-UUID: ",14));
        pthread_mutex_lock(&lock); command_completed++; if(!ok) command_errors++; pthread_mutex_unlock(&lock);
    }
    return result;
}

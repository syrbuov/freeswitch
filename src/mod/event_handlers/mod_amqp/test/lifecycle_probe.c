/* A separate Core process using the production DSO and real network workers. */
#define _GNU_SOURCE
#include <switch.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>

static void (*counts)(int *,int *,int *,int *,int *);
static void (*send_counts)(int *,int *);
static void (*command_counts)(int *,int *,int *);
static void (*arm)(void), (*release_gate)(void);
static int (*gate_entered)(void);
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
static int unload_entered, unload_done;
static switch_status_t unload_status;

static void symbol(void *out,size_t size,const char *name)
{
    void *p=dlsym(RTLD_DEFAULT,name);
    if(!p || size!=sizeof(p)) abort();
    memcpy(out,&p,size);
}
static int status_api(void)
{
    switch_stream_handle_t stream={0};
    int ok;
    SWITCH_STANDARD_STREAM(stream);
    ok=switch_api_execute("amqp","status",NULL,&stream)==SWITCH_STATUS_SUCCESS && stream.data &&
        strstr(stream.data,"state=ACTIVE") && strstr(stream.data,"commands=legacy-local-test");
    switch_safe_free(stream.data);
    return ok;
}
static int profile_metrics(const char *expected, int recovery)
{
    switch_stream_handle_t stream={0};
    cJSON *root=NULL, *array, *profile, *item;
    char *body;
    const char *groups[]={"producers","logging"};
    int ok=0,i;
    SWITCH_STANDARD_STREAM(stream);
    if(switch_api_execute("amqp","profiles",NULL,&stream)!=SWITCH_STATUS_SUCCESS ||
       !stream.data || strncmp(stream.data,"+OK mod_amqp profiles\n",22)) goto done;
    body=strchr(stream.data,'\n');
    if(!body || !(root=cJSON_Parse(body+1))) goto done;
    if(getenv("AMQP_PROBE_LEGACY_COMMAND")) {
        int calls,completed,errors;
        item=cJSON_GetObjectItem(root,"commands");
        if(!item || !item->valuestring || strcmp(item->valuestring,"legacy-local-test")) goto done;
        command_counts(&calls,&completed,&errors);
        ok=calls==2 && completed==2 && errors==0;
        goto done;
    }
    for(i=0;i<2;i++) {
        array=cJSON_GetObjectItem(root,groups[i]);
        if(cJSON_GetArraySize(array)!=1) goto done;
        profile=cJSON_GetArrayItem(array,0);
        item=cJSON_GetObjectItem(profile,"connection");
        if(!item || !item->valuestring || strcmp(item->valuestring,expected)) goto done;
        item=cJSON_GetObjectItem(profile,"worker_running");
        if(!item || !item->valueint) goto done;
        item=cJSON_GetObjectItem(profile,"connect_attempts");
        if(!item || !item->valuestring || strcmp(item->valuestring,recovery?"2":"1")) goto done;
        if(recovery) {
            item=cJSON_GetObjectItem(profile,"connect_failures");
            if(!item || !item->valuestring || strcmp(item->valuestring,"1")) goto done;
            item=cJSON_GetObjectItem(profile,"last_error");
            if(!item || !item->valuestring || strcmp(item->valuestring,"exchange_declare")) goto done;
        }
    }
    ok=1;
 done:
    cJSON_Delete(root);
    switch_safe_free(stream.data);
    return ok;
}

static void *reload_worker(void *data)
{
    switch_stream_handle_t stream={0};
    int *ok=data;
    SWITCH_STANDARD_STREAM(stream);
    *ok=switch_api_execute("amqp",NULL,NULL,&stream)==SWITCH_STATUS_SUCCESS && stream.data && strstr(stream.data,"+OK mod_amqp configuration reloaded");
    switch_safe_free(stream.data);
    return NULL;
}
static void *unload_worker(void *data)
{
    const char *error=NULL;
    (void)data;
    pthread_mutex_lock(&lock); unload_entered=1; pthread_mutex_unlock(&lock);
    unload_status=switch_loadable_module_unload_module(NULL,"mod_amqp",SWITCH_TRUE,&error);
    pthread_mutex_lock(&lock); unload_done=1; pthread_mutex_unlock(&lock);
    return NULL;
}
static int await_ready(const char *path)
{
    switch_time_t deadline=switch_time_now()+8000000;
    while(access(path,F_OK) && switch_time_now()<deadline) switch_sleep(1000);
    return access(path,F_OK)==0;
}
int main(int argc,char **argv)
{
    const char *error=NULL;
    const char *root=getenv("AMQP_PROBE_ROOT"), *module=getenv("AMQP_PROBE_MODULE");
    const char *mode=argc>1?argv[1]:"unload";
    switch_status_t result;
    switch_time_t start,elapsed;
    int c,j,e,b,r,rc=0,send_started=0,send_active=0;
    if(!root || !module) return 2;
    setvbuf(stdout,NULL,_IONBF,0);
    fprintf(stderr,"probe: initializing Core\n");
    SWITCH_GLOBAL_dirs.mod_dir=strdup(root);
    SWITCH_GLOBAL_dirs.conf_dir=strdup(root);
    SWITCH_GLOBAL_dirs.log_dir=strdup(root);
    SWITCH_GLOBAL_dirs.run_dir=strdup(root);
    SWITCH_GLOBAL_dirs.db_dir=strdup(root);
    SWITCH_GLOBAL_dirs.data_dir=strdup(root);
    switch_core_set_globals();
    if(switch_core_init_and_modload(SCF_LOG_DISABLE,SWITCH_TRUE,&error)!=SWITCH_STATUS_SUCCESS) return 10;
    /* Core starts softtimer asynchronously and sets RUNNING twice during its
     * initial clock sampling. Do not shut Core down in that startup window. */
    switch_sleep(200000);
    fprintf(stderr,"probe: loading module\n");
    symbol(&counts,sizeof(counts),"amqp_probe_counts");
    symbol(&send_counts,sizeof(send_counts),"amqp_probe_send_counts");
    symbol(&arm,sizeof(arm),"amqp_probe_arm");
    symbol(&release_gate,sizeof(release_gate),"amqp_probe_release");
    symbol(&gate_entered,sizeof(gate_entered),"amqp_probe_entered");
    symbol(&command_counts,sizeof(command_counts),"amqp_probe_command_counts");
    if(getenv("AMQP_PROBE_LEGACY_COMMAND") &&
       switch_loadable_module_load_module("/usr/local/freeswitch/mod","mod_commands",SWITCH_FALSE,&error)!=SWITCH_STATUS_SUCCESS) return 26;
    if(!strcmp(mode,"core-bgapi")) {
        switch_stream_handle_t stream={0};
        SWITCH_STANDARD_STREAM(stream);
        if(switch_console_execute("bgapi originate error/mod-amqp-local-test &park()",0,&stream)!=SWITCH_STATUS_SUCCESS) return 27;
        switch_safe_free(stream.data);
        /* Reproduce the background-job/Core teardown report without loading
         * mod_amqp. A delay is not a detached-thread completion barrier. */
        switch_sleep(500000);
        fprintf(stderr,"probe: Core-only bgapi; mod_amqp never loaded\n");
        result=switch_core_destroy();
        printf("mode=core-bgapi result=%d\n",(int)result);
        return result==SWITCH_STATUS_SUCCESS?0:28;
    }
    if(switch_loadable_module_load_module(module,"mod_amqp",SWITCH_FALSE,&error)!=SWITCH_STATUS_SUCCESS || !status_api()) return 11;
    fprintf(stderr,"probe: module active; waiting for broker stage\n");
    if(getenv("AMQP_PROBE_READY") && !await_ready(getenv("AMQP_PROBE_READY"))) return 12;
    {
        const char *expected=getenv("AMQP_PROBE_STATE");
        int recovery=getenv("AMQP_PROBE_RECOVERY") && !strcmp(getenv("AMQP_PROBE_RECOVERY"),"true");
        switch_time_t deadline=switch_time_now()+3000000;
        while(!profile_metrics(expected?expected:"ready",recovery) && switch_time_now()<deadline) switch_sleep(1000);
        if(!profile_metrics(expected?expected:"ready",recovery)) return 25;
        if(getenv("AMQP_PROBE_LEGACY_COMMAND")) {
            int calls,completed,errors;
            command_counts(&calls,&completed,&errors);
            printf("legacy_commands: calls=%d completed=%d errors=%d\n",calls,completed,errors);
        } else printf("profiles: state=%s recovery=%d workers_running=2\n",expected?expected:"ready",recovery);
    }
    if(!strcmp(mode,"publish") || !strcmp(mode,"process-publish")) {
        char *body=malloc(131073);
        int i;
        memset(body,'x',131072); body[131072]='\0';
        for(i=0;i<128;i++) {
            switch_event_t *event=NULL;
            if(switch_event_create(&event,SWITCH_EVENT_DTMF)!=SWITCH_STATUS_SUCCESS) return 13;
            switch_event_add_header_string(event,SWITCH_STACK_BOTTOM,"AMQP-Probe-Body",body);
            switch_event_deliver(&event);
        }
        free(body);
        {
            switch_time_t deadline=switch_time_now()+3000000;
            int before=-1;
            while(switch_time_now()<deadline) {
                send_counts(&send_started,&send_active);
                if(send_active && before==send_started) break;
                before=send_started;
                switch_sleep(50000);
            }
            if(!send_active || !send_started) return 24;
        }
    }
    start=switch_time_now();
    fprintf(stderr,"probe: starting %s\n",mode);
    if(!strcmp(mode,"race")) {
        pthread_t reload_thread,unload_thread;
        switch_time_t deadline;
        int ok=0,entered=0,done;
        arm();
        if(pthread_create(&reload_thread,NULL,reload_worker,&ok)) return 14;
        deadline=switch_time_now()+3000000;
        while(!gate_entered() && switch_time_now()<deadline) switch_sleep(1000);
        if(!gate_entered()) return 15;
        if(pthread_create(&unload_thread,NULL,unload_worker,NULL)) return 16;
        deadline=switch_time_now()+3000000;
        while(!entered && switch_time_now()<deadline) { pthread_mutex_lock(&lock); entered=unload_entered; pthread_mutex_unlock(&lock); switch_sleep(1000); }
        pthread_mutex_lock(&lock); done=unload_done; pthread_mutex_unlock(&lock);
        release_gate();
        pthread_join(reload_thread,NULL); pthread_join(unload_thread,NULL);
        result=unload_status;
        if(!entered || done || !ok) rc=17;
    } else if(!strcmp(mode,"process") || !strcmp(mode,"process-publish")) {
        result=switch_core_destroy();
    } else {
        result=switch_loadable_module_unload_module(NULL,"mod_amqp",SWITCH_FALSE,&error);
    }
    elapsed=switch_time_now()-start;
    counts(&c,&j,&e,&b,&r);
    printf("mode=%s result=%d workers=%d joined=%d early_pool_free=%d bindings=%d removed=%d publishes=%d in_publish_before_stop=%d elapsed_ms=%lld\n",mode,(int)result,c,j,e,b,r,send_started,send_active,(long long)(elapsed/1000));
    if(result!=SWITCH_STATUS_SUCCESS || c<(getenv("AMQP_PROBE_LEGACY_COMMAND")?1:2) || c!=j || e || b!=r || elapsed>5000000) rc=18;
    if(strcmp(mode,"process") && strcmp(mode,"process-publish")) {
        if(switch_loadable_module_exists("mod_amqp")==SWITCH_STATUS_SUCCESS || status_api()) rc=19;
        /* A second real load must be possible after all owners were destroyed. */
        if(!strcmp(mode,"cycle")) {
            if(switch_loadable_module_load_module(module,"mod_amqp",SWITCH_FALSE,&error)!=SWITCH_STATUS_SUCCESS || !status_api()) rc=20;
            if(switch_loadable_module_unload_module(NULL,"mod_amqp",SWITCH_FALSE,&error)!=SWITCH_STATUS_SUCCESS) rc=21;
            counts(&c,&j,&e,&b,&r);
            if(c!=4 || c!=j || e || b!=r) rc=22;
        }
        fprintf(stderr,"probe: destroying Core\n");
        if(switch_core_destroy()!=SWITCH_STATUS_SUCCESS) rc=23;
    }
    return rc;
}

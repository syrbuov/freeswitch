/*
* FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
* Copyright (C) 2005-2012, Anthony Minessale II <anthm@freeswitch.org>
*
* Version: MPL 1.1
*
* The contents of this file are subject to the Mozilla Public License Version
* 1.1 (the "License"); you may not use this file except in compliance with
* the License. You may obtain a copy of the License at
* http://www.mozilla.org/MPL/
*
* Software distributed under the License is distributed on an "AS IS" basis,
* WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
* for the specific language governing rights and limitations under the
* License.
*
* The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
*
* The Initial Developer of the Original Code is
* Anthony Minessale II <anthm@freeswitch.org>
* Portions created by the Initial Developer are Copyright (C)
* the Initial Developer. All Rights Reserved.
*
* Based on mod_skel by
* Anthony Minessale II <anthm@freeswitch.org>
*
* Contributor(s):
*
* Daniel Bryars <danb@aeriandi.com>
* Tim Brown <tim.brown@aeriandi.com>
* Anthony Minessale II <anthm@freeswitch.org>
* William King <william.king@quentustech.com>
* Mike Jerris <mike@jerris.com>
*
* mod_amqp.c -- Sends FreeSWITCH events to an AMQP broker
*
*/

#ifndef MOD_AMQP_H
#define MOD_AMQP_H

#include <switch.h>
#include "mod_amqp_filter.h"
#include <amqp.h>
#include <amqp_framing.h>
#include <amqp_tcp_socket.h>
#include <amqp_ssl_socket.h>

#ifndef _MSC_VER
#include <strings.h>
#endif

#define MAX_LOG_MESSAGE_SIZE 1024
#define AMQP_MAX_HOSTS 4

/* If you change MAX_ROUTING_KEY_FORMAT_FIELDS then you must change the implementation of makeRoutingKey where it formats the routing key using sprintf */
#define MAX_ROUTING_KEY_FORMAT_FIELDS 10
#define MAX_ROUTING_KEY_FORMAT_FALLBACK_FIELDS 5
#define MAX_AMQP_ROUTING_KEY_LENGTH 255

#define TIME_STATS_TO_AGGREGATE 1024
#define MOD_AMQP_DEBUG_TIMING 0
#define MOD_AMQP_DEFAULT_CONTENT_TYPE "text/json"


typedef struct {
    char routing_key[MAX_AMQP_ROUTING_KEY_LENGTH];
    char *pjson;
} mod_amqp_message_t;

typedef struct mod_amqp_connection_s {
  char *name;
  char *hostname;
  char *virtualhost;
  char *username;
  char *password;
  unsigned int port;
  unsigned int heartbeat; /* in seconds */
  amqp_boolean_t ssl_on;
  amqp_boolean_t ssl_verify_peer;
  amqp_connection_state_t state;

  struct mod_amqp_connection_s *next;
} mod_amqp_connection_t;

typedef struct mod_amqp_keypart_s {
  char *name[MAX_ROUTING_KEY_FORMAT_FALLBACK_FIELDS];
  int size;
} mod_amqp_keypart_t;

typedef struct {
  switch_event_types_t id;
  char* subclass;
} mod_amqp_events_t;

typedef enum {
  MOD_AMQP_FILTER_LEGACY = 0, MOD_AMQP_FILTER_RULES
} mod_amqp_filter_mode_t;

typedef enum {
  MOD_AMQP_PRODUCER_PREPARED, MOD_AMQP_PRODUCER_ACTIVATING,
  MOD_AMQP_PRODUCER_ACTIVE, MOD_AMQP_PRODUCER_RETAINED
} mod_amqp_producer_state_t;

typedef struct mod_amqp_producer_prepared_s mod_amqp_producer_prepared_t;

typedef struct {
  char *name;
  mod_amqp_filter_mode_t filter_mode;
  mod_amqp_filter_engine_t *filter_engine;
  /* Management-only state. Callback readiness is published before binding. */
  mod_amqp_producer_state_t activation_state;

  char *exchange;
  char *exchange_type;
  int exchange_durable;
  int exchange_auto_delete;
  int delivery_mode;
  int delivery_timestamp;
  char *content_type;
  mod_amqp_keypart_t format_fields[MAX_ROUTING_KEY_FORMAT_FIELDS+1];


  /* Array to store the possible event subscriptions */
  int event_subscriptions;
  switch_event_node_t *event_nodes[SWITCH_EVENT_ALL];
  mod_amqp_events_t events[SWITCH_EVENT_ALL];
  switch_event_node_t *eventNode;


  /* Because only the 'running' thread will be reading or writing to the two connection pointers
   * this does not 'yet' need a read/write lock. Before these structures can be destroyed,
   * the running thread must be joined first.
   */
  mod_amqp_connection_t *conn_root;
  mod_amqp_connection_t *conn_active;

  /* Rabbit connections are not thread safe so one connection per thread.
     Communicate with sender thread using a queue */
  switch_thread_t *producer_thread;
  switch_queue_t *send_queue;
  unsigned int send_queue_size;

  int reconnect_interval_ms;
  int circuit_breaker_ms;
  switch_time_t circuit_breaker_reset_time;
  switch_bool_t enable_fallback_format_fields;

  /* Protects running and circuit_breaker_reset_time; never held across unbind, join or AMQP I/O. */
  switch_mutex_t *state_mutex;
  switch_bool_t running;
  switch_memory_pool_t *pool;
  char *custom_attr;
} mod_amqp_producer_profile_t;

typedef struct {
  char *name;

  char *exchange;
  char *queue;
  char *binding_key;

  /* Queue properties */
  switch_bool_t passive;
  switch_bool_t durable;
  switch_bool_t exclusive;
  switch_bool_t auto_delete;

  /* Note: The AMQP channel is not reentrant this MUTEX serializes sending events. */
  mod_amqp_connection_t *conn_root;
  mod_amqp_connection_t *conn_active;

  int reconnect_interval_ms;

  /* Listener thread */
  switch_thread_t *command_thread;
  switch_thread_id_t command_thread_id;
  switch_bool_t command_thread_started;

  switch_mutex_t *mutex;
  switch_bool_t running;
  switch_memory_pool_t *pool;
  char *custom_attr;
} mod_amqp_command_profile_t;

typedef struct {
  char *name;

  char *exchange;
  char *exchange_type;
  int exchange_durable;
  int exchange_auto_delete;

  uint32_t log_level_mask;

  /* Note: The AMQP channel is not reentrant this MUTEX serializes sending events. */
  mod_amqp_connection_t *conn_root;
  mod_amqp_connection_t *conn_active;

  int reconnect_interval_ms;

  /* Logging thread */
  switch_thread_t *logging_thread;
  switch_queue_t *send_queue;
  unsigned int send_queue_size;

  switch_mutex_t *mutex;
  switch_bool_t running;
  char *custom_attr;
  switch_memory_pool_t *pool;
} mod_amqp_logging_profile_t;

typedef struct mod_amqp_globals_s {
  switch_memory_pool_t *pool;
  /* Management only: never acquired by producer callbacks or sender threads. */
  switch_mutex_t *lifecycle_mutex;
  switch_bool_t shutting_down;
  switch_bool_t logging_bound;

  switch_hash_t *producer_hash;
  switch_hash_t *command_hash;
  switch_hash_t *logging_hash;
} mod_amqp_globals_t;

extern mod_amqp_globals_t mod_amqp_globals;

/* utils */
switch_status_t mod_amqp_do_config(switch_bool_t reload);
switch_bool_t mod_amqp_is_command_thread(void);
int mod_amqp_log_if_amqp_error(amqp_rpc_reply_t x, char const *context);
int mod_amqp_count_chars(const char* string, char ch);
void mod_amqp_util_msg_destroy(mod_amqp_message_t **msg);

/* connection */
/* Pure configuration parsing: no AMQP handles, sockets or I/O. */
switch_status_t mod_amqp_connection_parse(mod_amqp_connection_t *config, switch_xml_t cfg, switch_memory_pool_t *pool);
switch_status_t mod_amqp_connection_create(mod_amqp_connection_t **conn, switch_xml_t cfg, switch_memory_pool_t *pool);
void mod_amqp_connection_destroy(mod_amqp_connection_t **conn);
void mod_amqp_connection_close(mod_amqp_connection_t *connection);
switch_status_t mod_amqp_connection_open(mod_amqp_connection_t *connections, mod_amqp_connection_t **active, char *profile_name, char *custom_attr);

/* command */
switch_status_t mod_amqp_command_destroy(mod_amqp_command_profile_t **profile);
switch_status_t mod_amqp_command_create(char *name, switch_xml_t cfg);
void * SWITCH_THREAD_FUNC mod_amqp_command_thread(switch_thread_t *thread, void *data);

/* producer */
/* create/destroy require lifecycle_mutex in the management thread, never in an event callback. */
void mod_amqp_producer_event_handler(switch_event_t* evt);
switch_status_t mod_amqp_producer_routing_key(mod_amqp_producer_profile_t *profile, char routingKey[MAX_AMQP_ROUTING_KEY_LENGTH],
					      switch_event_t* evt, mod_amqp_keypart_t routingKeyEventHeaderNames[]);
switch_status_t mod_amqp_producer_destroy(mod_amqp_producer_profile_t **profile);
switch_status_t mod_amqp_producer_create(char *name, switch_xml_t cfg);
/* Preparation owns an unpublished candidate. Activation consumes it exactly once,
 * even on failure; a failed cleanup leaves the owner in producer_hash. */
switch_status_t mod_amqp_producer_prepare(const char *name, switch_xml_t cfg, mod_amqp_producer_prepared_t **out);
switch_status_t mod_amqp_producer_activate(mod_amqp_producer_prepared_t *prepared);
void mod_amqp_producer_prepared_destroy(mod_amqp_producer_prepared_t **prepared);
void * SWITCH_THREAD_FUNC mod_amqp_producer_thread(switch_thread_t *thread, void *data);

char *amqp_util_encode(char *key, char *dest);

/* logging */
switch_status_t mod_amqp_logging_recv(const switch_log_node_t *node, switch_log_level_t level);
switch_status_t mod_amqp_logging_create(char *name, switch_xml_t cfg);
switch_status_t mod_amqp_logging_destroy(mod_amqp_logging_profile_t **prof);
void * SWITCH_THREAD_FUNC mod_amqp_logging_thread(switch_thread_t *thread, void *data);

#endif /* MOD_AMQP_H */


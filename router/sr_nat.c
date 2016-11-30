
#include <signal.h>
#include <string.h>
#include <assert.h>
#include "sr_nat.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "sr_utils.h"

int handle_nat_tcp(struct sr_instance *sr, struct sr_nat* nat, uint8_t *received_packet, char* iface_from);



int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);
    printf("intit st_nat!\n");


  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  nat->icmp_timeout_nat = 60;
  nat->tcp_est_timeout_nat = 7440;
  nat->tcp_trans_timeout_nat = 300;
  /* Initialize any variables here */

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

    pthread_mutex_lock(&(nat->lock));

    /* handle lookup here, malloc and assign to copy */
    struct sr_nat_mapping *copy = NULL;
    while(1){ /* loop through mappings */
        if (copy->aux_ext == aux_ext){
            printf("get map from external port!\n");
            break;
        }

        if (copy->next == NULL){
            /* already loop to the end, but still not get the mapping */
            copy = NULL;
            break;
        }

        else{
            /* keeping looking for next mapping */
            copy = copy->next;
        }
    }

    pthread_mutex_unlock(&(nat->lock));
    return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
    uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

    pthread_mutex_lock(&(nat->lock));

    /* handle lookup here, malloc and assign to copy. */
    struct sr_nat_mapping *copy = NULL;
    if (nat == 0){
        return NULL;
    }

    copy = nat->mappings;
    while(1){ /* loop through mappings */
        if ((copy->ip_int == ip_int) && (copy->aux_int == aux_int)){
            printf("get map from internal pair!\n");
            break;
        }

        if (copy->next == NULL){
            /* already loop to the end, but still not get the mapping */
            copy = NULL;
            break;
        }

        else{
            /* keeping looking for next mapping */
            copy = copy->next;
        }
    }
    pthread_mutex_unlock(&(nat->lock));
    return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
    uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

    pthread_mutex_lock(&(nat->lock));

    /* handle insert here, create a mapping, and then return a copy of it */
    struct sr_nat_mapping *mapping = nat->mappings;

    while(mapping != NULL){ /* loop through the mappings */
        mapping = mapping->next;
    }
    mapping = malloc(sizeof(struct sr_nat_mapping));
    mapping->type = type;
    mapping->ip_int = ip_int;
    mapping->aux_int = aux_int;
    mapping->next = NULL;

    if (type == nat_mapping_icmp){
        mapping->conns = NULL;
    }else{
        /* handle this later */
    }


    pthread_mutex_unlock(&(nat->lock));
    return mapping;
}

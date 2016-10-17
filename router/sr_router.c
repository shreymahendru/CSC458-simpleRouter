/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <inttypes.h>

#include <stdlib.h> 

#include <string.h> 

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */ 

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void create_send_arp_reply(struct sr_instance* sr, uint8_t * packet, struct sr_if* interface);
struct sr_rt* sr_IP_LPM(struct sr_instance *sr, uint32_t IP);

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  print_hdrs(packet, len);
  printf("%s\n", interface);
  printf("Printing the interface");

  /* fill in code here */
  print_hdrs(packet, len);
  
  printf("%s\n", interface);
  
  printf("Printing the interface");
  
  
  /* fill in code here */
  
  printf("Printing Headers:\n");
  
  print_hdrs(packet, len);
  
  /*SANITY CHECKS*/
  
  
  /*check if the ethernet frame is the greater than min length*/
  if(len <= sizeof(sr_ethernet_hdr_t)){
    return; 
  }
  
  /*getting the header since it is valid */
  sr_ethernet_hdr_t* frameHeader = (sr_ethernet_hdr_t*)packet;
  assert(frameHeader); 
  /*get the interface from the linked list*/
  struct sr_if* iface = sr_get_interface(sr, interface); 
  
  /*print the interface For DEBUGGING*/

  printf("Printing the interface\n");
  
  sr_print_if(iface);
  
  printf("\n");
  
  /*checking the validity of the interface*/
  
  assert(iface);
  
  /*check if the ethernet frame is the greater than min length*/
  if(len <= sizeof(sr_ethernet_hdr_t)){
    return;   
  }
  /*check which ethertype*/
  if(ethertype(packet) == ethertype_arp){
    printf("arp mode!\n");
    /*get arp packet*/
      sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      /* check arp type */
      if (ntohs(arp_hdr->ar_op) == arp_op_request){
        printf("ARP is a REQUEST!\n");  
      
        /*check if request is sending for me */
        if (arp_hdr->ar_tip == iface->ip){
          printf("this arp request is for me!\n");
          /* create arp reply (should we just go handle_arp function here?)*/
            create_send_arp_reply(sr, packet, iface);
          }
        else{
          printf("this arp is NOT for me! drop it\n");
          /* drop */
          return;
        }
      }
      else if (ntohs(arp_hdr->ar_op) == arp_op_reply){
        printf("ARP is a reply!\n"); 
            
      }
  }
  else if (ethertype(packet) == ethertype_ip) {
  
      printf("This MOFO is IP type\n");

      sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t))
      /*check if the ip packet is for us*/
      unsigned int ip_length  = len - sizeof(sr_ethernet_hdr_t)

      /*sanity cheack for ip packets*/
      if (sizeof(sr_ip_hdr_t) < ip_length){
          /*packet is too short, drop that shit*/
          return;
      }

      /*check ipv4*/
      if(ip_header->ip_v != 4){
        /*not IPv4*/
        return;
      }

      /*checksum check*/
      uint16_t checksum = cksum((void *) ip_header, sizeof(sr_ip_hdr_t));
      if (checksum != ip_header->ip_sum){
        return; 
      }
      
      /*getting the routing table entry which can be found by lpm form the routing table*/
      sr_rt* routing_table_entry = sr_ip_lpm(sr, ip_header->ip_dst); 

      


  }
}/* end sr_ForwardPacket */


void create_send_arp_reply(struct sr_instance* sr, uint8_t * packet, struct sr_if* interface){

  uint8_t *arp_packet = (uint8_t*) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));

  sr_ethernet_hdr_t* ether_head= (sr_ethernet_hdr_t*) arp_packet;

  sr_ethernet_hdr_t* eframe_recieved = (sr_ethernet_hdr_t*) packet;
  /*copying like this cause they are arrays*/
  /*setting host addr to what interface we recieved on*/
  memcpy(ether_head->ether_shost, interface->addr, ETHER_ADDR_LEN);
  /*setting destination to what the ethernet frame's source addr we recieved*/
  memcpy(ether_head->ether_dhost, eframe_recieved->ether_shost, ETHER_ADDR_LEN);

  ether_head->ether_type = htons(ethertype_arp);

  sr_arp_hdr_t* arp_head = (sr_arp_hdr_t*)(arp_packet + sizeof(sr_ethernet_hdr_t));

  sr_arp_hdr_t* arp_recieved = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  arp_head->ar_hrd = htons(arp_hrd_ethernet);             /* format of hardware address   */
  arp_head->ar_pro = htons(2048);             /* format of protocol address   */
  arp_head->ar_hln = ETHER_ADDR_LEN;             /* length of hardware address   */
  arp_head->ar_pln = 4;             /* length of protocol address   */
  arp_head->ar_op = htons(arp_op_reply);              /* ARP opcode (command)         */
  memcpy(arp_head->ar_sha, interface->addr, ETHER_ADDR_LEN);   /* sender hardware address      */
  arp_head->ar_sip = interface->ip;             /* sender IP address            */
  memcpy(arp_head->ar_tha, eframe_recieved->ether_shost, ETHER_ADDR_LEN);   /* target hardware address      */
  arp_head->ar_tip = arp_recieved->ar_sip;             /* target IP address= sender of arp_request*/ 

  uint32_t len = sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t);

  printf("PRINTING ARP REPLY\n");
  print_hdrs(arp_packet, len);

  int ret = sr_send_packet(sr, arp_packet, len, interface->name);

  if(ret == 0){
    printf("We made it\n");
  }
  else{
    printf("Got fucked\n");
  }

}

/*
takes arguments simple router instance, an ip, and the routing table
 performs LPM (bitwise AND) and returns destination IP  
*/

struct sr_rt* sr_IP_LPM(struct sr_instance *sr, uint32_t IP){
  struct sr_rt* rt_walker = 0;

  if(sr->routing_table == 0){
      printf(" ERROR IN sr_router.c : method sr_IP_LPM : *warning* Routing table empty \n");
      return;
  }

  rt_walker = sr->routing_table;

  while((rt_walker->next) {
    if ((inet_ntohl(rt_walker->dest->s_addr) & rt_walker->mask) == IP){
      break;
    }
    rt_walker = rt_walker->next;
    if (rt_walker == NULL){
        printf(" ERROR IN sr_router.c : method sr_IP_LPM : IP not found in routing table \n");
        return;
    }
  }

  
  return rt_walker;
}














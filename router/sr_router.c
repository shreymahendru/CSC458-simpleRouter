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
uint8_t *make_ip_packet( uint8_t * recieved_packet, unsigned int len);

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
  printf("Printing the interface\n");
  printf("%s\n", interface);
  
  
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
        fprintf(stderr, "ARP IS A REPLY!!!!!!!!!!!!!!!!!!");
        struct sr_arpreq* req; 
        /*print("%s\n", );*/
        print_addr_ip_int(ntohl(arp_hdr->ar_sip));
        req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
        if(req){
          struct sr_packet *pkt;
          for(pkt = req->packets; pkt!= NULL; pkt= pkt->next){
            sr_ethernet_hdr_t * head = (sr_ethernet_hdr_t*)pkt->buf;
            memcpy(head->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            int ret = sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
            if(ret == 0){
              printf("Packet Forwarded EZ\n");
              print_hdrs(pkt->buf, pkt->len);

              sr_arpcache_dump(&sr->cache);
              return;
            }
            else{
              printf("fuck up while forwarding\n");
              return;
            }
          }
          printf("Destroying the request!\n");
          sr_arpreq_destroy(&sr->cache, req);
        }

            
      }
  }
  else if (ethertype(packet) == ethertype_ip) {
  
      printf("This MOFO is IP type\n");

      sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      /*check if the ip packet is for us*/
      unsigned int ip_length  = len - sizeof(sr_ethernet_hdr_t);

      /*sanity cheack for ip packets*/
      if (sizeof(sr_ip_hdr_t) > ip_length){
          /*packet is too short, drop that shit*/
          printf("size too small\n");
          return;
      }

      /*check ipv4*/
      if(ip_header->ip_v != 4){
        /*not IPv4*/
        printf("not IPv4\n");
        return;
      }

      /*uint8_t * ip_packet = (void *) (packet + sizeof(sr_ethernet_hdr_t));*/
      /*checksum check*/
      printf("%d\n", ip_header->ip_hl);
      uint16_t old_sum = ip_header->ip_sum;
      ip_header->ip_sum = 0;
      uint16_t checksum = cksum(ip_header, 20);
      printf("check suuuuuuum = %d\n", checksum );
      printf("check suuuuuuum IIIIIPPPPPPPPPPPPs = %d\n", ip_header->ip_sum);
      if (checksum != old_sum){
        printf("checksum invalid\n");
        return; 
      }
      
      /*getting the routing table entry which can be found by lpm form the routing table*/
      char* matched_interface = sr_IP_LPM(sr, ip_header->ip_dst);
      if (matched_interface == NULL){
        printf("can't find interface\n");
        return;
      }
      struct sr_if* interface_info = sr_get_interface(sr, matched_interface); 

      /*look for arp entry for mac if you find send that shit fam no arp shit */
      struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, ip_header->ip_dst);

      if (entry){
        /*found in cache*/
        printf("Found in ARP Cache\n");
        /*make_ip_packet(packet, len);*/
        sr_ethernet_hdr_t* ether_header =(sr_ethernet_hdr_t*) packet;
        memcpy(ether_header->ether_shost, interface_info->addr, ETHER_ADDR_LEN);
        memcpy(ether_header->ether_dhost, entry->mac, ETHER_ADDR_LEN);
        sr_ip_hdr_t * iphead = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
        uint8_t ttl = iphead->ip_ttl;
        ttl = ttl - 1;
        if(ttl <= 0){
          /*send icmp here!*/
          printf("Ran out of ttl \n");
          return;
        }
        else{
          printf("Printing the lpm interface!!!!!!!! %s\n", matched_interface);
          print_addr_ip_int(ntohl(ip_header->ip_dst));
          ip_header->ip_ttl = ip_header->ip_ttl - -1;
          ip_header->ip_sum = 0;
          ip_header->ip_sum = cksum((void *) ip_header, 20);
          int ret = sr_send_packet(sr, packet, len, matched_interface);
            if(ret == 0){
              printf("Packet Forwarded by cache found shit EZ\n");
              print_hdrs(packet, len);
              return;
            }
            else{
              printf("fuck up while forwarding by chache found shit\n");
              return;
            }

        }


          /*change ethernet frame details here and source ip*/
          /*sr_send */
      }
      else{
        /*can't find in cache */
        printf("Can't find in ARP Cache\n");
        uint8_t * default_packet = make_ip_packet(packet, len);
        /*change dest mac to interface mac*/
        sr_ethernet_hdr_t * ether  =(sr_ethernet_hdr_t*) default_packet;
        memcpy(ether->ether_shost, interface_info->addr, ETHER_ADDR_LEN);

        sr_ip_hdr_t* ip_head = (sr_ip_hdr_t*) (default_packet + sizeof(sr_ethernet_hdr_t));
        uint8_t ttl = ip_head->ip_ttl;
        ttl = ttl - 1;
        if(ttl <= 0){
          /*send icmp here!*/
          printf("Ran out of ttl \n");
          return;
        }
        else{
          printf("Printing the lpm interface!!!!!!!! %s\n", matched_interface);
          print_addr_ip_int(ntohl(ip_header->ip_dst));
          ip_head->ip_ttl = ip_head->ip_ttl - -1;
          ip_head->ip_sum = 0;
          ip_head->ip_sum = cksum((void *) ip_head, 20);
          struct sr_arpreq *a =  sr_arpcache_queuereq(&sr->cache, ip_head->ip_dst,default_packet, len, matched_interface); 
          print_addr_ip_int(ntohl(a->ip));
        }   
        /*in the que*/
      }


      /*else put that piece of shit in the queue*/

      /*Then que takes care from there.... I hope..*/

      /*sr_arpcache_dump(&sr->cache);*/
  }
}/* end sr_ForwardPacket */


uint8_t *make_ip_packet( uint8_t * recieved_packet, unsigned int len){

  uint8_t * default_packet = malloc(len);

  /*copying the original to prevent loss of payload*/
  memcpy(default_packet, recieved_packet, len);

  return default_packet;


} 



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

char* sr_IP_LPM(struct sr_instance *sr, uint32_t IP){
  struct sr_rt* rt_walker = 0;

  if(sr->routing_table == 0){
      printf(" ERROR IN sr_router.c : method sr_IP_LPM : *warning* Routing table empty \n");
      return NULL;
  }

  rt_walker = sr->routing_table;

  while(rt_walker->next) {
    if ((rt_walker->dest.s_addr & rt_walker->mask.s_addr) == IP){
      break;
    }
    rt_walker = rt_walker->next;
    if (rt_walker == NULL){
        printf(" ERROR IN sr_router.c : method sr_IP_LPM : IP not found in routing table \n");
        return NULL;
    }
  }

  
  return rt_walker->interface;
}

void create_icmp(uint8_t *packet, uint8_t type, uint8_t code){
    
    /* get ip packet from orig ethernet frame */
    
    
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    
    /* move ptr to the data part of ip_packet */
    sr_icmp_hdr_t *icmp = (sr_icmp_hdr_t *)(ip_hdr + sizeof(sr_ip_hdr_t));
    
    /* test orgin icmp i got */
    /*print_hdr_icmp(icmp);*/
    
    /* process to copy info into icmp */
    
    icmp->icmp_type = type;
    icmp->icmp_code = code; 
    
    /* unsure about the usage of cksum! this probably wrong */
    icmp->icmp_sum = cksum(icmp, ICMP_DATA_SIZE);
    
    /* check copy result */
    /*print_hdr_icmp(icmp);*/
    
}











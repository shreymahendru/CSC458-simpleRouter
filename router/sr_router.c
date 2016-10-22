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

void handle_arp_request(struct sr_instance* sr, uint8_t* recieved_packet, unsigned int length, char* interface);
void handle_ip_packet(struct sr_instance * sr, uint8_t* recieved_packet, unsigned int len, char* interface);
struct sr_if* find_router_ips( struct sr_instance* sr, uint32_t IP);
void forward_ip_packet(struct sr_instance * sr, uint8_t * packet, unsigned int len, char * matched_interface);
void create_send_icmp_type3(struct sr_instance *sr, uint8_t *recieved_packet, int code, char* iface, unsigned int length);
char* sr_IP_LPM(struct sr_instance *sr, uint32_t IP);
void create_send_icmp_echo(struct sr_instance *sr, uint8_t *recieved_packet, char* iface, unsigned int length);
void handle_arp_reply( struct sr_instance *sr,uint8_t* packet,unsigned int  len, char * interface);

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

  /* fill in code here */

  /*print packet recieved*/
  print_hdrs(packet, len);

  if(len <= sizeof(sr_ethernet_hdr_t)){
    /*packet too short*/
    return; 
  }

  /*check if ip or arp*/  
  if(ethertype(packet) == ethertype_arp){
    printf("This is an arp packet!\n");
    
    sr_arp_hdr_t * arp_header = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    if (ntohs(arp_header->ar_op) == arp_op_request){
      printf("This ARP is a request!\n");
      handle_arp_request(sr, packet, len, interface);
    }
    else if (ntohs(arp_header->ar_op) == arp_op_reply){
      printf("This is ARP reply!\n");
      handle_arp_reply(sr, packet, len, interface);
      return;
    }

  }
  else if(ethertype(packet) == ethertype_ip){
    printf("This is an Ip packet\n");
    handle_ip_packet(sr, packet, len, interface);
    return;
  }


}/* end sr_ForwardPacket */


void handle_arp_reply( struct sr_instance *sr,uint8_t* packet,unsigned int  len, char * interface){
        printf("printing ARP REPLY!!!!!!\n");
        print_hdrs(packet, len );
        sr_arp_hdr_t * arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));  
        struct sr_arpreq* req; 
        req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
        
        if(req){
          printf("wtf?\n");

          struct sr_packet *pkt;
          for(pkt = req->packets; pkt!= NULL; pkt= pkt->next){
            sr_ethernet_hdr_t * head = (sr_ethernet_hdr_t*)pkt->buf;
            memcpy(head->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            printf("Sending packet!!!\n");
            print_hdrs(pkt->buf, len);
            int ret = sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
            if(ret == 0){
              printf("Packet Forwarded EZ\n");
              print_hdrs(pkt->buf, pkt->len);

              sr_arpcache_dump(&sr->cache);
             
            }
            else{
              printf("fuck up while forwarding\n");
              
            }
          }
          printf("Destroying the request!\n");
          sr_arpreq_destroy(&sr->cache, req);
          return; 
        }

            
      
}


void handle_ip_packet(struct sr_instance * sr, uint8_t* packet, unsigned int len, char* interface){

     sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
     unsigned int length_ip = len - sizeof(sr_ethernet_hdr_t) ;
     
     if( length_ip < sizeof(sr_ip_hdr_t)){
      printf("Size of ip packet too small\n");
      return; 
     }

      /*check ipv4*/
     if(ip_header->ip_v != 4){
      printf("IpPacket not v4\n");
      return;
     }

     /*checksum check*/
      uint16_t old_sum = ip_header->ip_sum;
      ip_header->ip_sum = 0;
      uint16_t checksum = cksum(ip_header, 20);
      if (checksum != old_sum){
        printf("Checksum invalid, dropping the packet!\n");
        return; 
      }

      /*setting checksum back*/
      ip_header->ip_sum = checksum;
      
      /*checking for routers interface ips*/
      struct sr_if* router_ip_matched = find_router_ips(sr, ip_header->ip_dst);
      if (router_ip_matched != NULL){
      /*giving it sr instance original packet recieved and interface it was recieved one and lenthd of the packet*/

      /*checck if it the icmp or not if not do some stuff*/
       if(ip_header->ip_p != 1){
          /*port unreachable*/
          create_send_icmp_type3(sr, packet, 3 ,interface, len);
          return;

        }

      printf("This is send to our routers IP sending a reply back\n");
      create_send_icmp_echo(sr, packet, interface, len);
      return;
      }

      /*not matched with routers ips*/

      /*getting the routing table entry which can be found by lpm form the routing table*/
      char* matched_interface = sr_IP_LPM(sr, ip_header->ip_dst);

      printf("MATCHED INTERFACE: %s\n", matched_interface);

      if (matched_interface == NULL){
        printf("can't find interface to send dropping the packet and sending an ICMP\n");
        /*create_send_icmp(sr, packet, 3, 0, matched_interface, len);*/
        create_send_icmp_type3(sr, packet, 0, interface, len);
        return;
      }

      forward_ip_packet(sr, packet, len, matched_interface);


}




void forward_ip_packet(struct sr_instance * sr, uint8_t * packet, unsigned int len, char * matched_interface){

    sr_ethernet_hdr_t * ether_head = (sr_ethernet_hdr_t *) packet ;
    print_addr_eth(ether_head->ether_shost);
    sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    print_addr_ip_int(ntohl(ip_header->ip_dst));
    struct sr_if* interface_info = sr_get_interface(sr, matched_interface); 


    uint8_t ttl = ip_header->ip_ttl;
    printf("%d\n", ttl );
    ttl--;
    printf("printinag %d\n", ttl );
    if (ttl <= 0){

      /*icmp ttl*/
      return; 
    }
    ip_header->ip_ttl = ttl; 

    ip_header->ip_sum = 0;

    ip_header->ip_sum = cksum(ip_header, 20);

    print_addr_ip_int(ntohl(ip_header->ip_dst));
    struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, ip_header->ip_dst);
    
    if (entry){
      printf("found in cache!\n");

      memcpy(ether_head->ether_dhost, entry->mac, ETHER_ADDR_LEN);
      memcpy(ether_head->ether_shost, interface_info->addr, ETHER_ADDR_LEN);
      sr_send_packet(sr, (uint8_t*) packet, len, matched_interface);
      /*free(packet);*/
      return;
    }
    else {
       printf("not in cache\n");
       memcpy(ether_head->ether_shost,interface_info->addr, ETHER_ADDR_LEN);
       /*memset(ether_head->ether_dhost, 255, ETHER_ADDR_LEN);*/
       print_hdrs(packet, len);

      
       sr_arpcache_queuereq(&sr->cache, ip_header->ip_dst, packet, len, matched_interface); 
       /*free(packet);*/
       return;

    }

     

      /*memcpy(ether_head->ether_shost, ) */

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

  while(rt_walker) {
    printf("------\n");
    print_addr_ip_int(IP);
    print_addr_ip_int(rt_walker->dest.s_addr);
    if ((rt_walker->dest.s_addr & rt_walker->mask.s_addr) == IP){
      print_addr_ip_int((rt_walker->dest.s_addr & rt_walker->mask.s_addr));
      print_addr_ip_int(IP);
      return rt_walker->interface;
    }
    rt_walker = rt_walker->next;
  }
  printf(" ERROR IN sr_router.c : method sr_IP_LPM : IP not found in routing table \n");
  return NULL;
}

struct sr_if* find_router_ips( struct sr_instance* sr, uint32_t IP){
  struct sr_if* if_walker = 0;
  if_walker = sr->if_list;

  while(if_walker)
  {
     if(ntohl( if_walker->ip)== ntohl(IP) ){
      printf("IP MATCHED WITH ROUTERS =\n");
      print_addr_ip_int(ntohl(IP));
      return if_walker; }
      if_walker = if_walker->next;
  }
  return NULL;
}


void handle_arp_request(struct sr_instance* sr, uint8_t* recieved_packet, unsigned int length, char* interface){

  sr_ethernet_hdr_t* eframe_recieved = (sr_ethernet_hdr_t*)recieved_packet;
  sr_arp_hdr_t* arp_recieved = (sr_arp_hdr_t*) (recieved_packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if* iface = sr_get_interface(sr, interface);
  
  if(arp_recieved->ar_tip != iface->ip){
      printf("This Arp request is not for us!\n");
      return;
  }

  /*Creating a ARP Reply Packet*/
  uint8_t *arp_packet = (uint8_t*) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));

  /*Defining ethernet header*/
  sr_ethernet_hdr_t* ether_head= (sr_ethernet_hdr_t*) arp_packet;


  /*setting MAC addr to what interface we recieved on, as host*/
  memcpy(ether_head->ether_shost, iface->addr, ETHER_ADDR_LEN);

  /*setting destination MAC addr to the senders MAC addr*/
  memcpy(ether_head->ether_dhost, eframe_recieved->ether_shost, ETHER_ADDR_LEN);

  /*type of ethernet frame as ARP*/
  ether_head->ether_type = htons(ethertype_arp);

  sr_arp_hdr_t* arp_head= (sr_arp_hdr_t*)(arp_packet + sizeof(sr_ethernet_hdr_t));

  arp_head->ar_hrd = htons(arp_hrd_ethernet);             /*format of hardware address*/
  arp_head->ar_pro = htons(2048);             /*format of protocol address*/
  arp_head->ar_hln = ETHER_ADDR_LEN;             /*length of hardware address*/
  arp_head->ar_pln = 4;             /* length of protocol address*/
  arp_head->ar_op = htons(arp_op_reply);              /* ARP opcode (command)*/
  memcpy(arp_head->ar_sha, iface->addr, ETHER_ADDR_LEN);   /*sender hardware address*/
  arp_head->ar_sip = iface->ip;             /* sender IP address*/
  memcpy(arp_head->ar_tha, eframe_recieved->ether_shost, ETHER_ADDR_LEN);   /*target hardware address*/
  arp_head->ar_tip = arp_recieved->ar_sip;             /* target IP address= sender of arp_request*/ 

  uint32_t len = sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t);

  printf("fuck?\n");
  print_hdrs(arp_packet, len);
  int ret = sr_send_packet(sr, arp_packet, len, iface->name);

  if(ret == 0){
    printf("We Sent an arp reply to: ");
    print_addr_ip_int(ntohl(arp_head->ar_tip));
  }
  else{
    printf("I messed up While sending ARP reply to: ");
    print_addr_ip_int(ntohl(arp_head->ar_tip));
  }

  free(arp_packet);

}



void create_send_icmp_echo(struct sr_instance *sr, uint8_t *recieved_packet, char* iface, unsigned int length){


    sr_ip_hdr_t *recieved_ip = (sr_ip_hdr_t *)(recieved_packet + sizeof(sr_ethernet_hdr_t));
    /*checking ICMP checksum*/
    sr_icmp_hdr_t *icmp_recieved = (sr_icmp_hdr_t *)(recieved_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    uint16_t old_cksum = icmp_recieved->icmp_sum;
    icmp_recieved->icmp_sum = 0;
    uint16_t sum = cksum((void *) icmp_recieved, ntohs(recieved_ip->ip_len) - sizeof(sr_ip_hdr_t)); 
    if(sum != old_cksum){
      printf("INVALID ICMP CHECKSUM! \n");
      return; 
    }

    /*payload length*/
    unsigned int recieved_data_length = length - sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
    uint8_t * recieved_data= (uint8_t*)(recieved_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
    
    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t) + recieved_data_length;  
    uint8_t *icmp_packet= (uint8_t*) malloc(len);

    /*Creating a ICMP Reply Packet*/
    /*creqating the ether header for icmp */
    sr_ethernet_hdr_t *icmp_ether = (sr_ethernet_hdr_t *) icmp_packet;

    struct sr_if* source_interface = sr_get_interface(sr, iface); 
    /*sending back to source*/
    memcpy(icmp_ether->ether_shost, source_interface->addr, ETHER_ADDR_LEN);
    icmp_ether->ether_type = htons(ethertype_ip);

    sr_ip_hdr_t *icmp_ip = (sr_ip_hdr_t *) (icmp_packet + sizeof(sr_ethernet_hdr_t)); 

    icmp_ip->ip_hl = recieved_ip->ip_hl;   /* header length */
    icmp_ip->ip_v = recieved_ip->ip_v;    /* version */
    icmp_ip->ip_tos = recieved_ip->ip_tos;
    icmp_ip->ip_len = recieved_ip->ip_len;     /* type of service */
    icmp_ip->ip_id = recieved_ip->ip_id;
    icmp_ip->ip_off = recieved_ip->ip_off;
    icmp_ip->ip_ttl = 64;     /* time to live */
    icmp_ip->ip_p = 1; /* protocol should be one as icmp */
    icmp_ip->ip_sum = 0;     
    icmp_ip->ip_src = recieved_ip->ip_dst;
    icmp_ip->ip_dst = recieved_ip->ip_src;
    icmp_ip->ip_sum = cksum((void *)icmp_ip, 20);
    /* move ptr to the data part of ip_packet */
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = 0;
    icmp_hdr->icmp_code = 0; 
    icmp_hdr->icmp_sum = 0;
    /*copying payload*/
    uint8_t* icmp_data = (uint8_t *) (icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
    memcpy(icmp_data, recieved_data, ntohs(icmp_ip->ip_len) - sizeof(sr_ip_hdr_t) - sizeof(sr_icmp_hdr_t));
    /*for checksum*/
    icmp_hdr->icmp_sum = cksum((void *)icmp_hdr, ntohs(icmp_ip->ip_len) - sizeof(sr_ip_hdr_t));


    struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, icmp_ip->ip_dst);
    
    if (entry){
      printf("found in cache!\n");

      memcpy(icmp_ether->ether_dhost, entry->mac, ETHER_ADDR_LEN);
      memcpy(icmp_ether->ether_shost, source_interface->addr, ETHER_ADDR_LEN);
      sr_send_packet(sr, (uint8_t*) icmp_packet, len, iface);
      /*free(packet);*/
      return;
    }
    else {
       printf("not in cache\n");
       memcpy(icmp_ether->ether_shost,source_interface->addr, ETHER_ADDR_LEN);
       /*memset(ether_head->ether_dhost, 255, ETHER_ADDR_LEN);*/

      
      sr_arpcache_queuereq(&sr->cache, icmp_ip->ip_dst , icmp_packet , length, iface); 
      free(icmp_packet);
       /*free(packet);*/
       return;

    }

}



void create_send_icmp_type3(struct sr_instance *sr, uint8_t *recieved_packet, int code, char* iface, unsigned int length){

   printf("creating a code %d icmp packet\n", code);
   
    sr_ethernet_hdr_t *recieved_ether = (sr_ethernet_hdr_t *) recieved_packet;
    sr_ip_hdr_t *recieved_ip = (sr_ip_hdr_t *)(recieved_packet + sizeof(sr_ethernet_hdr_t));

   /* unsigned int recieved_data_length = length - sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

    uint8_t *recieved_data= (uint8_t*)(recieved_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));*/
    
    /*malloc new icmp packet memory*/
    uint8_t *icmp_packet;
    unsigned int len = 0;
    len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);  
    icmp_packet= (uint8_t*) malloc(len);
   printf("total memory malloc is %d\n", len);
  /* printf("received_data_length is %d\n", recieved_data_length);*/
   printf("size of ethernet hdr is %d\n", sizeof(sr_ethernet_hdr_t));
   printf("size of sr_icmp_t3 is %d\n", sizeof(sr_icmp_t3_hdr_t));

    sr_ethernet_hdr_t *icmp_ether = (sr_ethernet_hdr_t *) icmp_packet;
    printf("PRINasiofbhaweiohfioqwehfopqhweion  IFACE%s\n", iface );
    struct sr_if* interface = sr_get_interface(sr, iface); 
    print_addr_eth(interface->addr);
    
    icmp_ether->ether_type = ntohs(ethertype_ip);
    sr_ip_hdr_t *icmp_ip = (sr_ip_hdr_t *) (icmp_packet + sizeof(sr_ethernet_hdr_t)); 
    icmp_ip->ip_hl = recieved_ip->ip_hl;   /* header length */
    icmp_ip->ip_v = recieved_ip->ip_v;    /* version */
    icmp_ip->ip_tos = recieved_ip->ip_tos;
    icmp_ip->ip_len = htons( sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));     /* type of service */
    icmp_ip->ip_id = recieved_ip->ip_id;
    icmp_ip->ip_off = recieved_ip->ip_off;
    icmp_ip->ip_ttl = 64;     /* time to live */
    icmp_ip->ip_p = 1; /* protocol should be one as icmp */
    icmp_ip->ip_sum = 0;     
    
    icmp_ip->ip_dst = recieved_ip->ip_src; 
    

     
    char * matched = sr_IP_LPM(sr, recieved_ip->ip_src);
    if (matched == NULL){
      return;
    }
    struct sr_if* matched_interface =sr_get_interface(sr, matched);
    icmp_ip->ip_src =  matched_interface->ip;
    memcpy(icmp_ether->ether_shost, matched_interface->addr, ETHER_ADDR_LEN);
    icmp_ip->ip_sum = cksum((void *)icmp_ip, 20);

    
    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = 3;
    icmp_hdr->icmp_code = code; 
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->unused = 0;
    icmp_hdr->next_mtu = 0;
    
    /*  for uint8_t data, it will be IP header + first 8 bytes of datagram (added to 28 = default ICMP DATA SIZE) */
      

    memcpy(icmp_hdr->data, recieved_ip, ICMP_DATA_SIZE);
    printf("size first copped is %d\n", sizeof(sr_ip_hdr_t));

   /* uint8_t *rest_data = (uint8_t*) ((icmp_hdr->data) + (sizeof(sr_ip_hdr_t)));
    memcpy(rest_data, recieved_data, ICMP_DATA_SIZE - sizeof(sr_ip_hdr_t));                                          
    printf("size second copyed is %d\n", ICMP_DATA_SIZE - sizeof(sr_ip_hdr_t));
  */
/*
    uint8_t * start_icmp = (uint8_t *) (icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));*/

/*    sr_icmp_t3_hdr_t *recieved_icmp = (sr_icmp_t3_hdr_t *)( recieved_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));*/
    icmp_hdr->icmp_sum = cksum((void *)icmp_hdr, sizeof(sr_icmp_t3_hdr_t)) ;

    /*unsigned int recieved_icmp_length = sizeof(recieved_icmp) + recieved_data_length;*/
    
   
   struct sr_arpreq *a =  sr_arpcache_queuereq(&sr->cache, icmp_ip->ip_dst , icmp_packet , len, iface); 
    


    free(icmp_packet);

}
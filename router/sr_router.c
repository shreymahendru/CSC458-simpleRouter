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
	
  /*get the interface from the linked list*/
  struct sr_if* iface = sr_get_interface(sr, interface); 
	
  /*print the interface For DEBUGGING*/

  printf("Printing the interface\n");
	
  sr_print_if(iface);
	
  printf("\n");
	
  /*checking the validity of the interface*/
	
  assert(iface);
	
	
  /*check which ethertype*/
	
  if(ethertype(packet) == ethertype_arp){
		printf("arp mode!\n");
		/*get arp packet*/
  		sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  		/* check arp type */
  		if (ntohs(arp_hdr->ar_op) == arp_op_request){
			printf("ARP REQUEST!\n");  
			/*check if request is sending for me */
			
			
			if (arp_hdr->ar_tip == iface->ip){
				
				printf("this arp request is for me!\n");
				/* create arp reply (should we just go handle_arp function here?)*/
				
				struct sr_arpentry *entry;
				entry = sr_arpcache_lookup(&sr->cache, arp_hdr->ar_sip);
  				if (entry){
  					/*found the entry*/
  				}else{
  					struct sr_arpreq *request;
  					request = sr_arpcache_queuereq(&sr->cache, arp_hdr->ar_tip, packet, len, iface->name);
  				}
			}else if(arp_hdr->ar_tip != iface->ip){
				printf("this arp is NOT for me! drop it\n");
				/* drop */
			}

	
  		}
  
  		else if (ntohs(arp_hdr->ar_op) == arp_op_reply){
			printf("ARP reply!\n"); 
			  		
  		}

	  
  }
	
  else if (ethertype(packet) == ethertype_ip) {
	
  		printf("This MOFO is IP type\n");
	
  }
  /*check if the ethernet frame is the greater than min length*/
  if(len <= sizeof(sr_ethernet_hdr_t)){
    return;   
  }
  /*getting the header since it is valid */
  sr_ethernet_hdr_t* frameHeader = (sr_ethernet_hdr_t*)packet;
  /*get the interface from the linked list*/
  struct sr_if* iface = sr_get_interface(sr, interface); 
  /*print the interface For DEBUGGING*/
  printf("Printing the interface\n");
  sr_print_if(iface);
  printf("\n");
  /*checking the validity of the interface*/
  assert(iface);

  /*check which ethertype*/
  if(ethertype(packet) == ethertype_arp){
    printf("THIS IS A MOFO ARP\n");
  }
  else if (ethertype(packet) == ethertype_ip) {
    printf("This MOFO is IP type\n");
  }
}/* end sr_ForwardPacket */

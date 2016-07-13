#include <pcap.h>
#include <stdio.h>
#include <libnet.h>

int main()
{
   pcap_t *handle;			/* Session handle */
   char *dev;			/* The device to sniff on */
   char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
   struct bpf_program fp;		/* The compiled filter */
   char filter_exp[] = "";	/* The filter expression */
   bpf_u_int32 mask;		/* Our netmask */
   bpf_u_int32 net;		/* Our IP */
   struct pcap_pkthdr* header;	/* The header that pcap gives us */
   struct libnet_ethernet_hdr *ethernet_hdr;
   struct libnet_ipv4_hdr *ipv4_hdr;
   struct libnet_tcp_hdr *tcp_hdr;

   const u_char *packet;		/* The actual packet */
   u_char *ptr; /* printing out hardware header info */
   int res;
   int i;

   /* Define thedevice */
   dev = pcap_lookupdev(errbuf);

   if (dev == NULL) {
       fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
       return(2);
   }
   /* Find the properties for the device */
   if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
       fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
       net = 0;
       mask = 0;
   }
   /* Open the session in promiscuous mode */
   handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
   if (handle == NULL) {
       fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
       return(2);
   }
   /* Compile and apply the filter */
   if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
       fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
       return(2);
   }
   if (pcap_setfilter(handle, &fp) == -1) {
       fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
       return(2);
   }
   /* Grab a packet */

   while(1){
     res = pcap_next_ex(handle, &header,&packet);
     /* Print its length */
     if(res< 0){
         printf("error occurred while reading the packet\n");
         break;
     }
     if(res == 0){
         printf("packets are being read from a live capture and the timeout expired\n");
         continue;
     }
     //interpret packet //

     //  print ethernet  //
     ethernet_hdr = (struct libnet_ethernet_hdr *) packet;
     if (ntohs(ethernet_hdr->ether_type) == ETHERTYPE_IP){
         printf("Ethernet type hex:%x dec:%d is an IP packet\n",
                         ntohs(ethernet_hdr->ether_type),
                         ntohs(ethernet_hdr->ether_type));
     }
     else{    //if not ip  , skip the packet
         continue;
     }

      ptr = ethernet_hdr->ether_shost;
      i = ETHER_ADDR_LEN ;
      printf("Src ethernet Address:  ");
      do{
              printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
         }while(--i>0);
      printf("\n");
      ptr = ethernet_hdr->ether_dhost;
      i = ETHER_ADDR_LEN;
      printf("Dst ethernet Address:  ");
      do{
          printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
      }while(--i>0);
      printf("\n");

      //  print ipv4  //
      packet = packet+14;
      ipv4_hdr = (struct libnet_ipv4_hdr *) packet;
      printf("Src IP Adress : %s\n", inet_ntoa(ipv4_hdr->ip_src));
      printf("Dst IP Adress : %s\n", inet_ntoa(ipv4_hdr->ip_dst));

      if( ipv4_hdr->ip_p == 6){ // tcp
          //  print tcp //
          packet += ipv4_hdr->ip_hl*4;
          tcp_hdr = (struct libnet_tcp_hdr *) packet;
          printf("Src TCP port : %hu\n",ntohs(tcp_hdr->th_sport));
          printf("Dst TCP port : %hu\n",ntohs(tcp_hdr->th_dport));

      }
      else{ //if not tcp
          continue;
      }
   }
   pcap_close(handle);
   return(0);
}

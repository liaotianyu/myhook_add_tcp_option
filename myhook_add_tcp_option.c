//***************************************************************
// http://blog.csdn.net/zhangskd/article/details/22678659
//
//	Hook function to be called.
//	We modify the packet and add tcp option in the packet
//***************************************************************

#include <linux/netfilter.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <uapi/linux/tcp.h>
#include <linux/netdevice.h>

static char my_buf[64];
static char option_tm[8] = {0xfd, 0x08, 0x03, 0x48, 0x5a, 0x5a, 0x5a, 0x5a};   //the tcp option that will be appended on tcp header

unsigned int my_hookfn(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))   //user defined function for adding tcp option
{
	struct 	iphdr           *iph    ;
	struct 	tcphdr          *tcph   ;
	struct  net_device	*dev    ;
	char                    *name   ;
        int                     hdr_len ;
        char                    *d      ;
        int                     i       ;

	iph     = ip_hdr(skb);
	tcph    = (struct tcphdr *) skb_transport_header(skb);
	dev     = skb->dev;
	name    = & dev->name;

	/* log the original src IP */
	//if( iph->daddr==0x0c0310ac && tcph->source==0x5000 ){
	//printk(KERN_INFO"debug post-routing dest IP %x\n", iph->daddr);
	//if( iph->daddr==0x035b8478 ){ 
	//if( iph->daddr==0x080310ac ){ //local pc
	//if( iph->daddr==0x6dd94b77 || iph->daddr==0x080310ac ){   //the condition for modify packet
	if( tcph->dest==0x5000 ){
		printk(KERN_INFO"debug post-routing dest IP=%x\n", iph->daddr);
		printk(KERN_INFO"debug post-routing skb->iphdr=\n" );
		d = skb_network_header(skb);
		for(i=0; i<60; i++) {
			printk("%02x", (*d)&0xff);  //debug info for print original packet content
			d++;
		}
		if( tcph->syn==1 ) {   //the condition for not modify packet
		        printk(KERN_INFO"debug syn packet come \n");
			return NF_ACCEPT;
		}
		if( skb_headroom(skb)>=22 ) {  //the condition for modify packet 
		        printk(KERN_INFO"debug post-routing len         =%x \n", skb->len       );
		        printk(KERN_INFO"debug post-routing data_len    =%x \n", skb->data_len  );
		        printk(KERN_INFO"debug post-routing mac_len     =%x \n", skb->mac_len   );
		        printk(KERN_INFO"debug post-routing hdr_len     =%x \n", skb->hdr_len   );
		        printk(KERN_INFO"debug post-routing head        =%x \n", skb->head      );
		        printk(KERN_INFO"debug post-routing data        =%x \n", skb->data      );
		        printk(KERN_INFO"debug post-routing tail        =%x \n", skb->tail      );
		        printk(KERN_INFO"debug post-routing end         =%x \n", skb->end       );
		        printk(KERN_INFO"debug iph ->ihl                =%x \n", iph ->ihl      );
		        printk(KERN_INFO"debug iph ->tot_len            =%x \n", iph ->tot_len  );
		        printk(KERN_INFO"debug tcph->doff               =%x \n", tcph->doff     );
			printk(KERN_INFO"inner_protocol                 =%x \n", skb->inner_protocol         );
			printk(KERN_INFO"inner_transport_header         =%x \n", skb->inner_transport_header );
			printk(KERN_INFO"inner_network_header           =%x \n", skb->inner_network_header   );
			printk(KERN_INFO"inner_mac_header               =%x \n", skb->inner_mac_header       );
			printk(KERN_INFO"transport_header               =%x \n", skb->transport_header       );
			printk(KERN_INFO"network_header                 =%x \n", skb->network_header         );
			printk(KERN_INFO"mac_header                     =%x \n", skb->mac_header             );
                	if( skb->data[0]==0x45 && iph->protocol==0x06 ) {  //ipv4 and tcp packet
                                hdr_len = (iph->ihl + tcph->doff)*4;    //original header length, ip header + tcp header
			        memcpy(my_buf, skb->data, 64 );	        //copy original header to tmp buf; copy 64B to tmp buf; 64B is bigger than hdr_len;
			        memcpy(my_buf+hdr_len, option_tm, 8);   //append new tcp option on original header to generate a new header;
				d = my_buf;
				for(i=0; i<(hdr_len+8); i++) {          //print the new header
					printk("%02x", (*d)&0xff);
					d++;
				}
		        	printk(KERN_INFO"debug step3 \n");
                                skb_pull( skb, hdr_len );               //remove original header
                                skb_push( skb, hdr_len+8 );             //add new header
			        memcpy(skb->data, my_buf, hdr_len+8 );	//copy new header into skb;
		        	printk(KERN_INFO"debug step4 \n");

			        //update header offset in skb
			        skb->transport_header = skb->transport_header -8 ;
			        skb->network_header   = skb->network_header   -8 ;
                                //update ip header and checksum
		                printk(KERN_INFO"debug step5 \n");
			        iph = ip_hdr(skb);  //update iph point to new ip header
			        iph->tot_len = htons(skb->len);
			        iph->check = 0;     //re-calculate ip checksum
			        iph->check = ip_fast_csum( iph, iph->ihl);
                                //update tcp header and checksum
		                printk(KERN_INFO"debug step6 \n");
	                        tcph =  (struct tcphdr *) skb_transport_header(skb); //update tcph point to new tcp header
		                printk(KERN_INFO"old tcp_checksum=%x \n", tcph->check );
	                        tcph->doff = tcph->doff+2;
    			        tcph->check = 0;
			        int datalen;
			        datalen = (skb->len - iph->ihl*4);  //tcp segment length
		                //printk(KERN_INFO"tcp datalen	=%x \n", datalen );
		                //printk(KERN_INFO"saddr		=%x \n", iph->saddr );
		                //printk(KERN_INFO"daddr		=%x \n", iph->daddr );
		                //printk(KERN_INFO"protocol	=%x \n", iph->protocol );
		                //printk(KERN_INFO"tcph    	=   \n"   );
			        //d = tcph;
			        //for(i=0; i<datalen; i++) {
			        //	printk("%02x", (*d & 0xff) );
			        //	d++;
			        //}
		                //printk(KERN_INFO"tcph    	end  \n"   );
		                //
		                ////re-calculate tcp checksum
		                //tcp checksum = tcp segment checksum and tcp pseudo-header checksum
    			        tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
    			                                      datalen, iph->protocol,
    			                                      csum_partial((char *)tcph, datalen, 0));
    			        skb->ip_summed = CHECKSUM_UNNECESSARY;  //the reason is not clear, but without it, it seems the hardware will re-calcuate the checksum
		                printk(KERN_INFO"new tcp_checksum               =%x \n", tcph->check    );
		                printk(KERN_INFO"debug step7 \n");
		                printk(KERN_INFO"debug post-routing len         =%x \n", skb->len       );
		                printk(KERN_INFO"debug post-routing data_len    =%x \n", skb->data_len  );
		                printk(KERN_INFO"debug post-routing mac_len     =%x \n", skb->mac_len   );
		                printk(KERN_INFO"debug post-routing hdr_len     =%x \n", skb->hdr_len   );
		                printk(KERN_INFO"debug post-routing head        =%x \n", skb->head      );
		                printk(KERN_INFO"debug post-routing data        =%x \n", skb->data      );
		                printk(KERN_INFO"debug post-routing tail        =%x \n", skb->tail      );
		                printk(KERN_INFO"debug post-routing end         =%x \n", skb->end       );
		                printk(KERN_INFO"debug iph ->ihl                =%x \n", iph ->ihl      );
		                printk(KERN_INFO"debug iph ->tot_len            =%x \n", iph ->tot_len  );
		                printk(KERN_INFO"debug tcph->doff               =%x \n", tcph->doff     );
			        printk(KERN_INFO"inner_protocol                 =%x \n", skb->inner_protocol         );
			        printk(KERN_INFO"inner_transport_header         =%x \n", skb->inner_transport_header );
			        printk(KERN_INFO"inner_network_header           =%x \n", skb->inner_network_header   );
			        printk(KERN_INFO"inner_mac_header               =%x \n", skb->inner_mac_header       );
			        printk(KERN_INFO"transport_header               =%x \n", skb->transport_header       );
			        printk(KERN_INFO"network_header                 =%x \n", skb->network_header         );
			        printk(KERN_INFO"mac_header                     =%x \n", skb->mac_header             );
       			        //d = skb_network_header(skb);
			        //for(i=0; i<(hdr_len+8); i++) {
			        //	printk("%02x", (*d)&0xff);
			        //	d++;
			        //}
		                printk(KERN_INFO"debug step8 \n");
                        }
	
                        //debug info
		        //printk(KERN_INFO"debug post-routing net_device=%s\n", name );
		        //printk(KERN_INFO"debug post-routing len=%d \n", skb->len );
		        //printk(KERN_INFO"debug post-routing head=%x \n", skb->head );
		        //printk(KERN_INFO"debug post-routing data=%x \n", skb->data );
		        //printk(KERN_INFO"debug post-routing tail=%x \n", skb->tail );
		        //printk(KERN_INFO"debug post-routing end=%x \n", skb->end );
		        //printk(KERN_INFO"debug post-routing data_len=%d \n", skb->data_len);
		        //printk(KERN_INFO"debug post-routing mac_len=%d \n", skb->mac_len);
		        //printk(KERN_INFO"debug post-routing hdr_len=%d \n", skb->hdr_len);
		        //printk(KERN_INFO"debug post-routing src IP %pI4\n", &iph->saddr);
		        //printk(KERN_INFO"debug post-routing src IP %x\n", iph->saddr);
		        //printk(KERN_INFO"debug post-routing dest IP %x\n", iph->daddr);
		        //printk(KERN_INFO"debug post-routing src port %x\n", tcph->source);
		        //printk(KERN_INFO"debug post-routing dest port %x\n", tcph->dest);
		        //printk(KERN_INFO"debug post-routing head_room=%x\n", skb_headroom(skb) );
		        //printk(KERN_INFO"debug post-routing tail_room=%x\n", skb_tailroom(skb) );
		        //d = skb_network_header(skb);
		        //printk(KERN_INFO"debug post-routing skb->iphdr=\n" );
		        //for(i=0; i<20; i++) {
		        //	printk("a=%d,%02x", i, (*d)&0xff);
		        //	d++;
		        //}
		        //printk(KERN_INFO"debug post-routing skb->tcphdr=\n" );
		        //for(i=0; i<20; i++) {
		        //	printk("b=%d,%02x", i, (*d)&0xff);
		        //	d++;
		        //}
		        //d = skb->data;
		        //printk(KERN_INFO"debug post-routing skb->data=\n" );
		        //for(i=0; i<100; i++) {
		        //	//printk("%02x", (*d)&0xff);
		        //	printk("c=%d,%02x", i, (*d)&0xff);
		        //	d++;
		        //}
                }
                else { printk(KERN_INFO"head room is not enough\n" ); }
	}
	/* modify the packet's src IP */
	//iph->saddr = in_aton("8.8.8.8");
	return NF_ACCEPT;
}

/* A netfilter instance to use */
static struct nf_hook_ops nfho = {
	.hook = my_hookfn,
	.pf = PF_INET,
	//.hooknum = NF_INET_PRE_ROUTING,
	.hooknum = NF_INET_POST_ROUTING, //process packet after routing process
	.priority = NF_IP_PRI_FIRST,
	.owner = THIS_MODULE,
};

static int __init sknf_init(void)
{
	if (nf_register_hook(&nfho)) {
		printk(KERN_ERR"nf_register_hook() failed\n");
		return -1;
	}
	return 0;
}

static void __exit sknf_exit(void)
{
	nf_unregister_hook(&nfho);
}

module_init(sknf_init);
module_exit(sknf_exit);
MODULE_AUTHOR("liaotianyu");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("add tcp option for output packets");


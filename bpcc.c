///////////////////////////////////////////////////////////////////////////////////
//
//	Bidirectional Passive Covert Channel
//
//	BCIT COMP 8045 - Major Project
//
//	Author: Mario Enriquez
//
//	Student Id: A00909441
//	
//	To run:
//		-make
//		-insmod (path)/bpcc.ko
//	To remove:
//		-rmmod (path)
//
///////////////////////////////////////////////////////////////////////////////////

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/device.h>
#include <linux/netfilter.h>

#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <endian.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mario Enriquez");
MODULE_DESCRIPTION("Bidirectional Passive Covert Channel");

struct nf_hook_ops nfho;
char *src_ip,*dst_ip,*in,*out;
uint32_t src,dst;

module_param(in,charp,0000);
MODULE_PARM_DESC(in,"Inside Network");
module_param(out,charp,0000);
MODULE_PARM_DESC(out,"Outside Network");
module_param(src_ip,charp,0000);
MODULE_PARM_DESC(src_ip,"Source IP");
module_param(dst_ip,charp,0000);
MODULE_PARM_DESC(dst_ip,"Destination IP");

uint32_t get_ip(const char *str){
	union {
		uint32_t u32;
		uint8_t arr[4];
	} x;
	char substr[4];
	int c[4],i,j=0,dot=0;
	for(i=0;i<strlen(str);i++){
		if(str[i]=='.'){
			substr[3]='\0';
			sscanf(substr,"%d",&c[dot]);
			dot++;
			j=0;
			memset(substr,0,4);
		}
		else {
			substr[j]=str[i];
			j++;
		}
	}
	sscanf(substr,"%d",&c[dot]);
	if(dot!=3){
		printk(KERN_INFO "Error ip not valid. %d.\n",dot);
		return -ENXIO;	
	}
	for (i=0;i<sizeof(c);i++){
		if(c<0){
			printk(KERN_INFO "Error ip not valid.\n");
			return -ENXIO;
		}
	}
	x.arr[0]=(uint8_t) c[3];
	x.arr[1]=(uint8_t) c[2];
	x.arr[2]=(uint8_t) c[1];
	x.arr[3]=(uint8_t) c[0];
	return x.u32;
}

unsigned int hook_func(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	struct iphdr *iph;
	struct tcphdr *tcph;
	int seq,ack;
	uint32_t new_seq,new_ack;
	union {
		uint32_t u32;
		uint8_t arr[4];
	} x,y;
	iph = (struct iphdr*)skb_network_header(skb);
	if(iph->protocol==IPPROTO_TCP){
		printk(KERN_INFO "Received a TCP packet!!!\n");
		if(src==be32toh(iph->saddr) && dst == be32toh(iph->daddr)){
			printk(KERN_INFO "From Network:%s",in->name);
			tcph = (struct tcphdr*)skb_transport_header(skb);
			x.u32=be32toh(tcph->seq);
			y.u32=be32toh(tcph->ack_seq);
			seq=(int)x.u32;
			ack=(int)y.u32;
			new_seq=htobe32(~seq);
			new_ack=htobe32(~ack);
			printk(KERN_INFO "seq:= %x\n",(tcph->seq));
			printk(KERN_INFO "new seq:= %x\n",(new_seq));
			printk(KERN_INFO "ack:= %x\n",(tcph->ack_seq));
			printk(KERN_INFO "new ack:= %x\n",(new_ack));
			tcph->seq=new_seq;
			tcph->ack_seq=new_ack;
			printk(KERN_INFO "Flag Syn status:%x\n",tcph->syn)
		}
		if(dst==be32toh(iph->saddr) && src == be32toh(iph->daddr)){
			printk(KERN_INFO "From private network 2:");
			tcph = (struct tcphdr*)skb_transport_header(skb);
			x.u32=be32toh(tcph->seq);
			y.u32=be32toh(tcph->ack_seq);
			seq=(int)x.u32;
			ack=(int)y.u32;
			new_seq=htobe32(~seq);
			new_ack=htobe32(~ack);
			printk(KERN_INFO "seq:= %x\n",(tcph->seq));
			printk(KERN_INFO "new seq:= %x\n",(new_seq));
			printk(KERN_INFO "ack:= %x\n",(tcph->ack_seq));
			printk(KERN_INFO "new ack:= %x\n",(new_ack));
			tcph->seq=new_seq;
			tcph->ack_seq=new_ack;
		}		
	}
	return NF_ACCEPT;
}

static int __init start(void){
	if(!src_ip){
		printk(KERN_INFO "...Source IP not selected. Exiting.");
		return -ENXIO;
	}
	if(!dst_ip){
		printk(KERN_INFO "...Destination IP not selected. Exiting.");
		return -ENXIO;
	}
	src=get_ip(src_ip);
	dst=get_ip(dst_ip);
	nfho.hook=hook_func;
	nfho.hooknum=0;
	nfho.pf=PF_INET;
	nfho.priority=0;
	nf_register_hook(&nfho);
	printk(KERN_INFO "Starting Covert Channel...\n");
	return 0;
}

static void __exit cleanup(void){
	nf_unregister_hook(&nfho);
	printk(KERN_INFO "...Removing Covert Channel.\n");
}

module_init(start);
module_exit(cleanup);

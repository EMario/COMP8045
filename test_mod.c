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

#include <linux/net.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/socket.h>
#include <linux/sockios.h>

#include <net/neighbour.h>
#include <net/ip_fib.h>
#include <net/flow.h>
#include <net/arp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mario Enriquez");
MODULE_DESCRIPTION("Bidirectional Passive Covert Channel");

struct nf_hook_ops nfho;
//C0 A8 0A 0A
//C0 A8 0A 01

struct fib_table *fib_get_table(struct net *net, u32 id){
	struct fib_table *tb;
	struct hlist_head *head;
	unsigned int h;
	if(id == 0)
		id = RT_TABLE_MAIN;
	h= id & (FIB_TABLE_HASHSZ - 1);
	
	head = &net->ipv4.fib_table_hash[h];
	hlist_for_each_entry_rcu(tb, head, tb_hlist){
		if(tb->tb_id == id)
			return tb;
	}
	return NULL;
}

static struct neighbour *ipv4_neigh_lookup(const struct dst_entry *dst, struct sk_buff *skb, const void *daddr){
	struct net_device *dev = dst->dev;
	const __be32 *pkey = daddr;
	const struct rtable *rt;
	struct neighbour *n;

	rt = (const struct rtable *) dst;
	if (skb)
		pkey = &ip_hdr(skb)->daddr;
	n = __ipv4_neigh_lookup(dev, *(__force u32 *)pkey);
	if(n)
		return n;
	return NULL;
}

/*************************************************************************************************
Based the fib_table_lookup from net/ipv4/devinet.c function __ip_dev_find
*************************************************************************************************/
unsigned int hook_func(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	struct iphdr *iph;
	struct dst_entry *dst;
	struct neighbour *n;
	iph = (struct iphdr*)skb_network_header(skb);
	if(iph->protocol==IPPROTO_TCP){
		printk(KERN_INFO "TCP Packet Received!!!\n");
		dst=skb_dst(skb);
		n=ipv4_neigh_lookup(dst,skb,&iph->daddr);
		printk(KERN_INFO "TCP destination address: %x!!!\n",iph->daddr);
		printk(KERN_INFO "To Device [%s].\n",out->name);
		if(n==NULL){
			printk(KERN_INFO "Lookup failure!!!\n");
		} else {
			printk(KERN_INFO "Lookup success!!!\n");
		}
	}
	return NF_ACCEPT;
}

void test_mod(void){
	struct net_device *dev;
	struct net *n;
	struct neighbour *ngh;
	//struct arpreq r;
	union {
		uint32_t u32;
		uint8_t arr[4];
	} addr1,addr2;
	read_lock(&dev_base_lock);
	dev=first_net_device(&init_net);
	printk(KERN_INFO "FOUND [%s]\n", dev->name);
	dev = next_net_device(dev);
	printk(KERN_INFO "FOUND [%s]\n", dev->name);
	read_unlock(&dev_base_lock);
	n=dev_net(dev);
	addr1.u32=0xC0A80A0A;
	addr2.u32=0xC1081A0A;
	ngh=__ipv4_neigh_lookup(dev, addr1.u32);
	if(ngh!=NULL)
		printk(KERN_INFO "Table result is NULL");
	/*if(!(ngh->nud_state&(NUD_CONNECTED|NUD_DELAY|NUD_PROBE))){
		printk(KERN_INFO "Not Connected\n");
	} else {
		printk(KERN_INFO "Connected\n");
	}*/
	ngh=__ipv4_neigh_lookup(dev, addr2.u32);
	/*if(!(ngh->nud_state&(NUD_CONNECTED))){
		printk(KERN_INFO "Not Connected\n");
	} else {
		printk(KERN_INFO "Connected\n");
	}*/
	//arp_ioctl(n,SIOCGARP,&r);
}

static int __init start(void){
	nfho.hook=hook_func;
	nfho.hooknum=4;
	nfho.pf=PF_INET;
	nfho.priority=0;
	nf_register_hook(&nfho);
	printk(KERN_INFO "Starting Covert Channel...\n");
	//test_mod();
	return 0;
}

static void __exit cleanup(void){
	nf_unregister_hook(&nfho);
	printk(KERN_INFO "...Removing Covert Channel.\n");
}

module_init(start);
module_exit(cleanup);


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
//		-insmod (path)/bipcc.ko
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

struct node { //Linked list which will allow us to keep track of the packets
	uint32_t src_ip; //Key
	uint16_t src_port; //Key
	uint32_t curr_in_seq; 
	uint32_t curr_out_seq;
	uint32_t next_in_seq;
	uint32_t next_out_seq;
	int flag;	//Contains current flag of the packet
	char og_dev[IFNAMSIZ]; //if the node is expecting an answer value is 1
	short int del;
	short int subnet;//means if it's one of the gateways directly connected to the destination
	struct node* next;
};

struct node* head=NULL;
struct node* curr=NULL;
struct nf_hook_ops nfho_post, nfho_pre, nfho_fwd;
static short int debug_mode=0;

module_param(debug_mode,short,S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(debug_mode,"Debug Mode on/off");

uint32_t switch_order(uint32_t n){
	uint8_t aux;
	union{
		uint32_t u32;
		uint8_t arr[4];
	} x;
	x.u32=n;
	aux=x.arr[0];
	x.arr[0]=x.arr[3];
	x.arr[3]=aux;
	aux=x.arr[1];
	x.arr[1]=x.arr[2];
	x.arr[2]=aux;
	return x.u32;
}

uint32_t encode_uint32(uint32_t dec_value){
	uint32_t enc_value;
	enc_value=0xFFFFFFFF-dec_value;
	return enc_value;
}

uint32_t decode_uint32(uint32_t enc_value){
	uint32_t dec_value;
	dec_value=0xFFFFFFFF-enc_value;
	return dec_value;
}

void add_node(uint32_t src_ip,uint16_t src_port, uint32_t seq,uint32_t ack,int flag,short int subnet,const char dev_name[IFNAMSIZ]){
	//Linked list node starter, it's created when a SYN packet comes through
	struct node *new_node = (struct node*) kmalloc (sizeof(struct node),GFP_USER);
	int next_seq;
	new_node->src_ip=src_ip;
	new_node->src_port=src_port;
	new_node->curr_in_seq=seq;
	next_seq=switch_order(seq);
	next_seq++;
	next_seq=switch_order(next_seq);
	new_node->next_in_seq=next_seq;
	new_node->curr_out_seq=ack;
	new_node->next_out_seq=ack;
	new_node->flag=flag;
	strcpy(new_node->og_dev,dev_name);
	new_node->del=0; //deletion flag
	new_node->subnet=subnet;
	new_node->next=head;
	head=new_node;
}


void print_all_nodes(void){
	struct node* curr = head;
	if(head == NULL){
		return;
	}
	while(curr->next!=NULL){
		printk(KERN_INFO "IP:%x PORT:%x SEQ:%x N_SEQ:%x ACK:%x N_ACK:%x.\n",curr->src_ip,curr->src_port,curr->curr_in_seq,curr->curr_out_seq,curr->next_in_seq,curr->next_out_seq);
		curr=curr->next;
	}
	printk(KERN_INFO "IP:%x PORT:%x SEQ:%x N_SEQ%x ACK:%x N_ACK:%x.\n",curr->src_ip,curr->src_port,curr->curr_in_seq,curr->curr_out_seq,curr->next_in_seq,curr->next_out_seq);
	
}

struct node* find_node_subnet(uint32_t src_ip, uint16_t src_port){
	//finds if node exists in the subnet
	struct node* curr = head;
	if(head == NULL){
		return NULL;
	}
	while(curr->next!=NULL){
		if(curr->src_ip==src_ip){
			if(curr->src_port==src_port){
				if(curr->subnet==1){
					return curr;
				}
			}	
		}
		curr=curr->next;
	}
	if(curr->src_ip==src_ip){
		if(curr->src_port==src_port){
			if(curr->subnet==1){
				return curr;
			}
		}	
	}
	return NULL;
}


struct node* find_node(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint32_t dst_port, const char in_name[IFNAMSIZ],uint32_t seq,uint32_t ack){
	struct node* curr = head;
	uint32_t seq_val,ip_val;
	uint16_t port_val;
	if(head == NULL){
		return NULL;
	}

	while(curr->next!=NULL){
		if(strcmp(curr->og_dev,in_name)==0){
			seq_val=seq;
			ip_val=src_ip;
			port_val=src_port;
			if(curr->subnet!=1){
				seq_val=decode_uint32(seq_val);
			}
		} else {
			seq_val=ack;
			ip_val=dst_ip;
			port_val=dst_port;
			if(curr->subnet!=2){
				seq_val=decode_uint32(seq_val);
			}
		}
		if(curr->src_ip==ip_val){
			if(curr->src_port==port_val){
				if(curr->curr_in_seq==seq_val || curr->next_in_seq==seq_val){
					return curr;
				}
			}	
		}
		curr=curr->next;
	}
	if(strcmp(curr->og_dev,in_name)==0){
		seq_val=seq;
		ip_val=src_ip;
		port_val=src_port;
		if(curr->subnet!=1){
			seq_val=decode_uint32(seq_val);
		}
	} else {
		seq_val=ack;
		ip_val=dst_ip;
		port_val=dst_port;
		if(curr->subnet!=2){
			seq_val=decode_uint32(seq_val);
		}
	}
	printk(KERN_INFO "Adress:%x, %x\n",curr->src_ip,ip_val);
	printk(KERN_INFO "Port:%x, %x\n",curr->src_port,port_val);
	printk(KERN_INFO "SEQ:%x, %x, ACK: %x\n",curr->curr_in_seq,seq_val, ack);
	if(curr->src_ip==ip_val){
		if(curr->src_port==port_val){
			if(curr->curr_in_seq==seq_val || curr->next_in_seq==seq_val){
				return curr;
			}
		}	
	}
	return NULL;
}

void delete_node(uint32_t src_ip, uint16_t src_port){
	struct node *curr = head;
	struct node *previous = NULL;
	if(head == NULL){
		printk(KERN_INFO "Nothing to delete.\n");
		return;
	}

	while (curr->src_ip!=src_ip && curr->src_port!=src_port){
		if(curr->next == NULL){
			return;
		} else {
			previous = curr;
			curr = curr->next;
		}
	}
	curr->del=true;
}

void erase_nodes(void){
	struct node *curr = head;
	struct node *previous = NULL;
	if(head == NULL){
		printk(KERN_INFO "Nothing to delete.\n");
		return;
	}

	while (curr!=NULL){
		previous = curr;
		curr = curr->next;
		kfree(previous);
	}
	printk(KERN_INFO "Deleted all entries.");
}

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

static struct neighbour *ipv4_neigh_lookup(const void *addr, const struct net_device *net_dev){
	struct net_device *dev = (struct net_device*)net_dev;
	const __be32 *pkey = addr;
	struct neighbour *n;
	n = __ipv4_neigh_lookup(dev, *(__force u32 *)pkey);
	if(n)
		return n;
	return NULL;
}

int get_flags(struct tcphdr *tcph){
	int flags=(int) tcph->urg * 100000;
	flags+=(int) tcph->ack * 10000;
	flags+=(int) tcph->psh * 1000;
	flags+=(int) tcph->rst * 100;
	flags+=(int) tcph->syn * 10;
	flags+=(int) tcph->fin * 1;
	return flags;
}

unsigned int hook_func_fwd(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	struct neighbour *neigh;
	struct iphdr *iph;	
	struct tcphdr *tcph;
	struct node *curr_node;
	int flags=0,subnet_src=0,subnet_dst=0,subnet=0,size;
	iph = (struct iphdr*)skb_network_header(skb);
	if(iph->protocol==IPPROTO_TCP){
		printk(KERN_INFO "TCP PACKET FORWARDING...\n");		
		tcph = (struct tcphdr*)skb_transport_header(skb);
		flags=get_flags(tcph);
		if(flags==10){ 
			// SYN PACKET RECEIVED
			neigh=ipv4_neigh_lookup(&iph->saddr,in);
			if(neigh!=NULL){
				subnet_src=1;
				subnet=1;
			}
			neigh=ipv4_neigh_lookup(&iph->daddr,out);
			if(neigh!=NULL){
				subnet_dst=1;
				subnet=2;
			}
			if(subnet_src!=1){
				printk(KERN_INFO "SEQ=%x, ACK=%x\n",tcph->seq,tcph->ack_seq);
				tcph->seq=decode_uint32(tcph->seq);
				tcph->ack_seq=decode_uint32(tcph->ack_seq);
				printk(KERN_INFO "SEQ=%x, ACK=%x\n",tcph->seq,tcph->ack_seq);
			}
			curr_node=find_node_subnet(iph->saddr,tcph->source);
			if(curr_node!=NULL){
				if(curr_node->del!=1 && curr_node->subnet==1){
					printk(KERN_INFO "Dropping the packet, port and ip in use.\n");
					return NF_DROP;
				}
			}
			curr_node=find_node(iph->saddr, tcph->source, iph->daddr, tcph->dest, in->name,tcph->seq, tcph->ack_seq);
			if(curr_node==NULL){
				add_node(iph->saddr, tcph->source,tcph->seq,tcph->ack_seq,flags,subnet,in->name);
			} else {
				printk(KERN_INFO "Dropping the packet, packet and seq exists.\n");
				//return NF_DROP;
			}
			if(subnet_dst!=1){
				printk(KERN_INFO "SEQ=%x, ACK=%x\n",tcph->seq,tcph->ack_seq);
				tcph->seq=encode_uint32(tcph->seq);
				tcph->ack_seq=encode_uint32(tcph->ack_seq);
				printk(KERN_INFO "SEQ=%x, ACK=%x\n",tcph->seq,tcph->ack_seq);
			}
		} else {
			printk(KERN_INFO "SEQ=%x, ACK=%x\n",tcph->seq,tcph->ack_seq);
			//print_all_nodes();
			curr_node=find_node(iph->saddr, tcph->source, iph->daddr, tcph->dest, in->name,tcph->seq, tcph->ack_seq);
			if(curr_node==NULL){
				printk(KERN_INFO "Dropping the packet, packet not found.\n");
				//return NF_DROP;
			} else {
				printk(KERN_INFO "Packet found!!!");
				if(curr_node->del==1){
					if(curr_node->flag!=10001 && flags!=10000){
						printk(KERN_INFO "Dropping the packet.\n");
						//return NF_DROP;
					}
				}
			}
			size=0;
			/*size=ntohs(iph->tot_len) - (tcph->doff*4) - (iph->ihl*4);
			if(curr_node->subnet!=1){
				printk(KERN_INFO "SEQ=%x, ACK=%x\n",tcph->seq,tcph->ack_seq);
				tcph->seq=decode_uint32(tcph->seq);
				tcph->ack_seq=decode_uint32(tcph->ack_seq);
				printk(KERN_INFO "SEQ=%x, ACK=%x\n",tcph->seq,tcph->ack_seq);
			}
			if(flags==10010){//SYN/ACK
				if(strcmp(in->name,curr->og_dev)==0){
					curr_node->curr_in_seq=tcph->seq;
					curr_node->next_in_seq=tcph->seq+1;
				} else {
					curr_node->curr_out_seq=tcph->ack_seq;
					curr_node->next_out_seq=tcph->ack_seq+1;
				}
				curr->flag=10010;
			} else if (flags==10000){//ACK
				size=ntohs(iph->tot_len) - (tcph->doff*4) - (iph->ihl*4);
				if(strcmp(in->name,curr->og_dev)==0){
					curr_node->curr_in_seq=tcph->seq;
					curr_node->next_in_seq=tcph->seq+size;
				} else {
					curr_node->curr_out_seq=tcph->ack_seq;
					curr_node->next_out_seq=tcph->ack_seq+size;
				}
				if(curr->flag!=10001){
					curr->flag=10000;
				} else {
					curr->del=1;
				}
			} else if (flags==1){//FIN
				if(strcmp(in->name,curr->og_dev)==0){
					curr_node->curr_in_seq=tcph->seq;
					curr_node->next_in_seq=tcph->seq;
				} else {
					curr_node->curr_out_seq=tcph->ack_seq;
					curr_node->next_out_seq=tcph->ack_seq;
				}
				curr->flag=1;
			} else if (flags==10001){//FIN/ACK
				if(strcmp(in->name,curr->og_dev)==0){
					curr_node->curr_in_seq=tcph->seq;
					curr_node->next_in_seq=tcph->seq+1;
				} else {
					curr_node->curr_out_seq=tcph->ack_seq;
					curr_node->next_out_seq=tcph->ack_seq+1;
				}
				curr->flag=10001;
			} else if (flags==11000){//PUSH/ACK
				size=ntohs(iph->tot_len) - (tcph->doff*4) - (iph->ihl*4);
				if(strcmp(in->name,curr->og_dev)==0){
					curr_node->curr_in_seq=tcph->seq;
					curr_node->next_in_seq=tcph->seq+size;
				} else {
					curr_node->curr_out_seq=tcph->ack_seq;
					curr_node->next_out_seq=tcph->ack_seq+size;
				}

			} else if (flags==1000){//PUSH
				size=ntohs(iph->tot_len) - (tcph->doff*4) - (iph->ihl*4);
				if(strcmp(in->name,curr->og_dev)==0){
					curr_node->curr_in_seq=tcph->seq;
					curr_node->next_in_seq=tcph->seq+size;
				} else {
					curr_node->curr_out_seq=tcph->ack_seq;
					curr_node->next_out_seq=tcph->ack_seq+size;
				}

			}
			if(curr_node->subnet!=2){
				printk(KERN_INFO "SEQ=%x, ACK=%x\n",tcph->seq,tcph->ack_seq);
				tcph->seq=encode_uint32(tcph->seq);
				tcph->ack_seq=encode_uint32(tcph->ack_seq);
				printk(KERN_INFO "SEQ=%x, ACK=%x\n",tcph->seq,tcph->ack_seq);
			}
*/		}
	}
	return NF_ACCEPT;
}

/*************************************************************************************************
Based the fib_table_lookup from net/ipv4/devinet.c function __ip_dev_find
*************************************************************************************************/
/*unsigned int hook_func_post(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct neighbour *n;
	struct node *curr_node;
	iph = (struct iphdr*)skb_network_header(skb);
	if(iph->protocol==IPPROTO_TCP){
		printk(KERN_INFO "TCP Packet Received Postrouting!!!\n");
		tcph = (struct tcphdr*)skb_transport_header(skb);
		curr_node=find_node(iph->saddr,tcph->source);
		if(curr_node==NULL){
			return NF_DROP;
		}
		if(curr_node->flag==10){
			n=ipv4_neigh_lookup(&iph->daddr,out);
			printk(KERN_INFO "TCP destination address: %x!!!\n",iph->daddr);
			printk(KERN_INFO "To Device [%s].\n",out->name);
			if(n!=NULL){
				curr_node->subnet=1;
				update_node(curr_node);
			}			
		}
		if(curr_node->subnet==0){
			tcph->seq= encode_uint32(tcph->seq);
			tcph->ack_seq= encode_uint32(tcph->ack_seq);
		}
	}
	return NF_ACCEPT;
}

unsigned int hook_func_pre(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct neighbour *neigh;
	struct node *curr_node;
	int flags;
	short int subnet;
	iph = (struct iphdr*)skb_network_header(skb);
	if(iph->protocol==IPPROTO_TCP){
		printk(KERN_INFO "TCP Packet Received Prerouting!!!\n");
		tcph = (struct tcphdr*)skb_transport_header(skb);
		flags=get_flags(tcph);

		//Check the flags and decide what do to with the packet
		if(flags==10){ // SYN PACKET
			curr_node=find_node_subnet(iph->saddr,tcph->source);
			neigh=ipv4_neigh_lookup(&iph->saddr,in);
			if(neigh==NULL){
				//Packet didn't come from a subnet, need to get the true SEQ
				subnet=0;
				tcph->seq= decode_uint32(tcph->seq);
				tcph->ack_seq= decode_uint32(tcph->ack_seq);
				printk(KERN_INFO "Decoding packet.\n");
				
			} else {
				subnet=1;
			}
			if(curr_node!=NULL){
				if(curr_node->subnet==1 && subnet==1){
					return NF_DROP;
				}
			}
			//Create node
			add_node(iph->saddr, tcph->source,tcph->seq,tcph->ack_seq,flags,subnet,in->name);
		} else {
			curr_node=find_node_seq(iph->saddr,tcph->source,tcp->seq);
			if(curr_node==NULL){
				return NF_DROP;
			}
			if(curr_node->del==1){
				return NF_DROP;
			}
			//Check if packet needs to be decoded
			if(curr_node->subnet==0){
				tcph->seq= decode_uint32(tcph->seq);
				tcph->ack_seq= decode_uint32(tcph->ack_seq);
			}
			if(curr_node->){

			}
			if(flags==10010){//SYN/ACK
				
			} else if (flags==10000){//ACK

			} else if (flags==1){//FIN

			} else if (flags==10001){//FIN/ACK

			} else if (flags==11000){//PUSH/ACK

			} else if (flags==1000){//PUSH

			}
		}
		
	}
	return NF_ACCEPT;
}*/


static int __init start(void){
	nfho_fwd.hook=hook_func_fwd;
	nfho_fwd.hooknum=2;//forward
	nfho_fwd.pf=PF_INET;
	nfho_fwd.priority=0;
	nf_register_hook(&nfho_fwd);
	printk(KERN_INFO "Starting Covert Channel...\n");
	return 0;
}

static void __exit cleanup(void){
	nf_unregister_hook(&nfho_fwd);
	erase_nodes();
	printk(KERN_INFO "...Removing Covert Channel.\n");
}

module_init(start);
module_exit(cleanup);

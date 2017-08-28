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
#include <linux/rcupdate.h>

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

struct tcp_log { //Linked list which will allow us to keep track of the packets
	uint32_t saddr; //Key Source Address
	uint16_t dport; //Key Destination Port
	uint32_t seq; 
	uint32_t seq_ack;
	uint32_t n_seq;
	uint32_t n_seq_ack;
	uint32_t p_seq;
	uint32_t p_seq_ack;
	int flags;	//Contains current flag of the packet
	char in[IFNAMSIZ]; 
	char out[IFNAMSIZ]; 
	short int ack_recv;
	char subnet[IFNAMSIZ];//If address goes or comes to a subnet, put subnet name
	struct tcp_log* n_log;
};

struct dest_log { //log for destinations, updates every syn
	uint32_t daddr;
	uint32_t dport;
	long n_sec[20];
	int size;
	struct dest_log* n_log;
};

struct tcp_log* head=NULL;
struct dest_log* d_head=NULL;
struct nf_hook_ops nfho_fwd;
static short int debug_mode=0;
//static long int cooldown=10000000000;

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

void add_entry(uint32_t daddr,uint32_t dport){
	struct timespec *ts=NULL;
	struct dest_log* new_log=  (struct dest_log*) kmalloc (sizeof(struct dest_log),GFP_USER);
	new_log->daddr=daddr;
	new_log->dport=dport;
	getnstimeofday(ts);
	new_log->n_sec[0]=ts->tv_nsec;
	new_log->size=1;
	new_log->n_log=d_head;
	d_head=new_log;
}

void add_log(uint32_t saddr,uint16_t dport, uint32_t seq, uint32_t seq_ack, uint32_t n_seq, uint32_t n_seq_ack, uint32_t p_seq, uint32_t p_seq_ack, int flags, const char in[IFNAMSIZ],const char out[IFNAMSIZ],const char subnet[IFNAMSIZ]){
	struct tcp_log *new_log = (struct tcp_log*) kmalloc (sizeof(struct tcp_log),GFP_USER);
	new_log->saddr=saddr; //Key Source Address
	new_log->dport=dport; //Key Source Port
	new_log->seq=seq; 
	new_log->seq_ack=seq_ack;
	new_log->n_seq=n_seq;
	new_log->n_seq_ack=n_seq_ack;
	new_log->p_seq=p_seq;
	new_log->p_seq_ack=p_seq_ack;
	new_log->flags=flags; 
	strcpy(new_log->in,in);
	strcpy(new_log->out,out);
	new_log->ack_recv=0;
	strcpy(new_log->subnet,subnet);
	new_log->n_log=head;	
	head=new_log;
}

void print_logs(void){
	struct tcp_log *curr = head;
	int cont=0;
	if(curr==NULL){
		return;
	}
	while(cont==0){
		printk("--LOG--");
		printk(KERN_INFO "SEQ=%x NSEQ=%x PSEQ=%x IN=%s\n",curr->seq,curr->n_seq,curr->p_seq,curr->in);
		printk(KERN_INFO "ACK=%x NACK=%x PACK=%x OUT=%s\n",curr->seq_ack,curr->n_seq_ack,curr->p_seq_ack,curr->out);
		if(curr->n_log==NULL){
			cont=1;
		} else {
			curr=curr->n_log;
		}
	}
}


struct tcp_log* find_node(const char in[IFNAMSIZ],const char out[IFNAMSIZ],uint32_t seq,uint32_t seq_ack,int flags){
	struct tcp_log *curr = head;
	int cont=0;
	uint32_t dec_seq,dec_ack;
	if(curr==NULL){
		return NULL;
	}
	while(cont==0){
		dec_seq=seq;
		dec_ack=seq_ack;
		if(strcmp(curr->in,in)==0 && strcmp(curr->out,out)==0){
			if(strcmp(curr->subnet,in)!=0){
				printk(KERN_INFO "Decoding 1...\n");
				dec_seq=decode_uint32(dec_seq);
				dec_ack=decode_uint32(dec_ack);
			}
			if(curr->seq_ack==dec_ack && (curr->seq==dec_seq || (flags==10010 && curr->flags==10010))){
				return curr;
			}
		} else if(strcmp(curr->in,out)==0 && strcmp(curr->out,in)==0) {
			if(strcmp(curr->subnet,in)!=0){
				printk(KERN_INFO "Decoding 2...\n");
				dec_seq=decode_uint32(dec_seq);
				dec_ack=decode_uint32(dec_ack);
			}
			if(curr->seq_ack==dec_seq && (curr->seq==dec_ack || (flags==10010 && curr->flags==10010))){
				return curr;
			}		
		}
		if(curr->n_log==NULL){
			cont=1;
		} else {
			curr=curr->n_log;
		}
	}
	return NULL;
}

void delete_prev_nodes(uint32_t saddr, uint16_t dport,int prev_no){
	struct tcp_log *curr = head;
	struct tcp_log *del = NULL;
	struct tcp_log *prev = NULL;
	int cont=0,i=0;
	if(curr==NULL){
		printk(KERN_INFO "Nothing to delete.\n");
		return;
	}
	while (cont!=1){
		if(curr->n_log==NULL){
			cont=1;
			if(curr->saddr==saddr && curr->dport==dport){
				if(i>=prev_no){
					kfree(curr);
					prev->n_log=NULL;
				}
				i++;
			}
		} else {
			if(curr->saddr==saddr && curr->dport==dport){
				if(i>=prev_no && curr->ack_recv==1){
					del=curr;
					curr=curr->n_log;
					prev->n_log=curr;
					kfree(del);
				} 
				i++;
			} else {
				prev = curr;
				curr = curr->n_log;	
			}
		}
	}
	printk(KERN_INFO "Deleted all entries.\n");
}

void erase_logs(void){
	struct tcp_log *curr = head;
	struct tcp_log *prev = NULL;
	if(curr==NULL){
		printk(KERN_INFO "Nothing to delete.\n");
		return;
	}

	while (curr!=NULL){
		prev = curr;
		curr = curr->n_log;
		kfree(prev);
	}
	printk(KERN_INFO "Deleted all entries.\n");
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

int handle_tcp_logs(struct iphdr* iph,struct tcphdr* tcph,const struct net_device *in, const struct net_device *out){
	struct neighbour *neigh;
	struct tcp_log* curr_log;
	int flags,aux,t_size;
	char subnet[IFNAMSIZ]="";
	flags=get_flags(tcph);
	t_size=ntohs(iph->tot_len) - (tcph->doff*4) - (iph->ihl*4);
	if(flags==10){
		printk(KERN_INFO "SYN PACKET\n");
		printk(KERN_INFO "Source dev:%s, Source ip:%x, Source port:%x",in->name,iph->saddr,tcph->source);
		printk(KERN_INFO "Destination dev:%s, Source ip:%x, Source port:%x",out->name,iph->daddr,tcph->dest);
		neigh=ipv4_neigh_lookup(&iph->saddr,in);
		if(neigh!=NULL){			
			printk(KERN_INFO "Input Device directly connected!!!\n");
			strcpy(subnet,in->name);
		} else {
			printk(KERN_INFO "Decoding Received SEQ and ACK...\n");
			printk(KERN_INFO "Received SEQ: %x, Received ACK:%x\n",tcph->seq,tcph->ack_seq);
			tcph->seq=decode_uint32(tcph->seq);
			tcph->ack_seq=decode_uint32(tcph->ack_seq);
			printk(KERN_INFO "Decoded SEQ: %x, Decoded ACK:%x\n",tcph->seq,tcph->ack_seq);
		}
		if(tcph->ack_seq!=0){
			return -1;
		}
		neigh=ipv4_neigh_lookup(&iph->daddr,out);
		if(neigh!=NULL){			
			printk(KERN_INFO "Output Device directly connected!!!\n");
			strcpy(subnet,out->name);
		}
		curr_log=find_node(in->name,out->name,tcph->seq,tcph->ack_seq,flags);
		if(curr_log!=NULL){
			if(curr_log->flags==10001 && curr_log->ack_recv==1){
				printk(KERN_INFO "Found log but deleted. Deleting all previous entries.\n");
				//delete previous entries
			} else {
				printk(KERN_INFO "Found log, still active.\n");
				return 0;
			}
		}
		aux=switch_order(tcph->seq);
		aux=aux+1;
		aux=switch_order(aux);
		add_log(iph->saddr,tcph->dest,tcph->seq,-2,-1,aux,-1,-1,flags,in->name,out->name,subnet);
		add_log(iph->saddr,tcph->dest,-2,aux,-1,-1,tcph->seq,-2,10010,out->name,in->name,subnet);
		if(strcmp(subnet,out->name)!=0){
			printk(KERN_INFO "Encoding...\n");
			printk(KERN_INFO "Received SEQ: %x, Received ACK:%x\n",tcph->seq,tcph->ack_seq);
			tcph->seq=encode_uint32(tcph->seq);
			tcph->ack_seq=encode_uint32(tcph->ack_seq);
			printk(KERN_INFO "Encoded SEQ: %x, Encoded ACK:%x\n",tcph->seq,tcph->ack_seq);
		}
	} else {
		printk(KERN_INFO "Packet number: %i\n",flags);
		curr_log=find_node(in->name,out->name,tcph->seq,tcph->ack_seq,flags);
		if(curr_log==NULL){
			printk(KERN_INFO "Packet not found.\n");
			return -1;
		}
		if(strcmp(curr_log->subnet,in->name)!=0){
			printk(KERN_INFO "Decoding...\n");
			printk(KERN_INFO "Received SEQ: %x, Received ACK:%x\n",tcph->seq,tcph->ack_seq);
			tcph->seq=decode_uint32(tcph->seq);
			tcph->ack_seq=decode_uint32(tcph->ack_seq);
			printk(KERN_INFO "Decoded SEQ: %x, Decoded ACK:%x\n",tcph->seq,tcph->ack_seq);
		}
		if(tcph->fin==1 || tcph->syn==1){ //SYN or FIN
			t_size++;	
		}
		if(t_size>0){
			if(flags==10010){
				aux=switch_order(tcph->seq);
				aux=aux+1;
				aux=switch_order(aux);
				add_log(curr_log->saddr,curr_log->dport,tcph->ack_seq,aux,-1,-1,tcph->seq,tcph->ack_seq,10000,out->name,in->name,curr_log->subnet);
				curr_log->ack_recv=1;
				curr_log->seq=tcph->seq;
				curr_log->n_seq=curr_log->seq_ack;
				curr_log->n_seq_ack=aux;
			} else { 
				if(tcph->psh==1){
					curr_log->ack_recv=1;	
				}
				aux=switch_order(tcph->seq);
				aux=aux+t_size;
				aux=switch_order(aux);
				add_log(curr_log->saddr,curr_log->dport,tcph->ack_seq,aux,-1,-1,curr_log->seq,curr_log->seq_ack,flags,out->name,in->name,curr_log->subnet);
				curr_log->n_seq=tcph->ack_seq;
				curr_log->n_seq_ack=aux;
			}
		} else {
			if(tcph->ack==1){
				curr_log->ack_recv=1;
			}
		}
		printk(KERN_INFO "SUBNET:%s\n",curr_log->subnet);
		printk(KERN_INFO "dev:%s->%s\n",in->name,out->name);
		if(strcmp(curr_log->subnet,out->name)!=0){
			printk(KERN_INFO "Encoding...\n");
			printk(KERN_INFO "Received SEQ: %x, Received ACK:%x\n",tcph->seq,tcph->ack_seq);
			tcph->seq=encode_uint32(tcph->seq);
			tcph->ack_seq=encode_uint32(tcph->ack_seq);
			printk(KERN_INFO "Encoded SEQ: %x, Encoded ACK:%x\n",tcph->seq,tcph->ack_seq);
		}
	}
	return 0;
}


unsigned int hook_func_fwd(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	struct iphdr *iph;	
	struct tcphdr *tcph;
	iph = (struct iphdr*)skb_network_header(skb);
	if(iph->protocol==IPPROTO_TCP){
		rcu_read_lock();
		printk(KERN_INFO "-------------------------------------\n");	
		printk(KERN_INFO "TCP PACKET RECEIVED...\n");		
		tcph = (struct tcphdr*)skb_transport_header(skb);
		if(handle_tcp_logs(iph,tcph,in,out)==-1){
			rcu_read_unlock();
			printk(KERN_INFO "...TCP PACKET DROPPED!!!\n");
			return NF_DROP;			
		}
		rcu_read_unlock();
		printk(KERN_INFO "");
	}
	return NF_ACCEPT;
}

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
	print_logs();
	erase_logs();
	printk(KERN_INFO "...Removing Covert Channel.\n");
}

module_init(start);
module_exit(cleanup);

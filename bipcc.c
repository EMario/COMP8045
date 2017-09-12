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
	uint32_t seq; //Key
	uint32_t seq_ack; //Key
	uint32_t n_seq; //Next Key numbers
	uint32_t n_seq_ack; //Next Key numbers
	uint32_t p_seq;
	uint32_t p_seq_ack;
	int flags;	//Contains current flag of the packet
	char in[IFNAMSIZ]; 
	char out[IFNAMSIZ]; 
	short int ack_recv;
	char subnet[IFNAMSIZ];//If address goes or comes to a subnet, put subnet name
	uint32_t saddr;
	uint32_t daddr; 
	uint16_t sport; 
	uint16_t dport; 
	struct tcp_log* n_log;
};

struct syn_log { //log for SYN packets
	uint32_t seq; //Key
	uint32_t seq_ack; //Key must be 0
	struct syn_log* n_log;
};

struct tcp_log* head=NULL;
struct syn_log* syn_head=NULL;
struct nf_hook_ops nfho_fwd;
static short int debug_mode=0;
static int CSUM_VAL=5;

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

uint16_t csum16(const uint16_t *data,int size){
	uint32_t sum;
	uint16_t result;
	sum=0x0;
	while(size>0){
		sum+=*data++;
		size--;
	}
	sum=(sum>>16)+(sum & 0xffff);
	sum=sum+(sum>>16);
	result=(uint16_t)~sum;
	return result;

}

struct tcp_log* add_log(uint32_t saddr,uint32_t daddr,uint16_t sport,uint16_t dport, uint32_t seq, uint32_t seq_ack, uint32_t n_seq, uint32_t n_seq_ack, uint32_t p_seq, uint32_t p_seq_ack, int flags, const char in[IFNAMSIZ],const char out[IFNAMSIZ],const char subnet[IFNAMSIZ]){
	struct tcp_log *new_log = (struct tcp_log*) kmalloc (sizeof(struct tcp_log),GFP_USER);
	new_log->saddr=saddr;
	new_log->daddr=daddr; 
	new_log->sport=sport;
	new_log->dport=dport;
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
	return new_log;
}

struct syn_log* add_syn_log(uint32_t seq, uint32_t seq_ack){
	struct syn_log *new_log = (struct syn_log*) kmalloc (sizeof(struct syn_log),GFP_USER);
	new_log->seq=seq; 
	new_log->seq_ack=seq_ack;
	new_log->n_log=syn_head;	
	syn_head=new_log;
	return new_log;
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
	if(curr==NULL){
		return NULL;
	}
	while(cont==0){
		if(strcmp(curr->in,in)==0 && strcmp(curr->out,out)==0){
			if(curr->seq_ack==seq_ack && (curr->seq==seq || (flags==10010 && curr->flags==10010))){
				return curr;
			}
		} else if(strcmp(curr->in,out)==0 && strcmp(curr->out,in)==0) {
			if(curr->seq_ack==seq && (curr->seq==seq_ack || (flags==10010 && curr->flags==10010))){
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
	struct tcp_log *curr_log,*next_log,*prev_log;
	int flags,aux,t_size;
	char subnet[IFNAMSIZ]="";
	uint16_t csum_data[]={0x0,tcph->source,tcph->dest,iph->id,iph->tot_len};
	union{
		uint16_t half[2];
		uint32_t full;
	}seq,ack;
	flags=get_flags(tcph);
	t_size=ntohs(iph->tot_len) - (tcph->doff*4) - (iph->ihl*4);
	neigh=ipv4_neigh_lookup(&iph->saddr,in);
	printk(KERN_INFO "Packet id: %i\n",iph->id);
	printk(KERN_INFO "Flags: %d\n",flags);
	printk(KERN_INFO "Source dev:%s, Source ip:%x, Source port:%x\n",in->name,iph->saddr,tcph->source);
	printk(KERN_INFO "Destination dev:%s, Dest ip:%x, Dest port:%x\n",out->name,iph->daddr,tcph->dest);
	printk(KERN_INFO "dev:%s->%s\n",in->name,out->name);
	if(neigh!=NULL){			
		printk(KERN_INFO "Input Device directly connected!!!\n");
		printk(KERN_INFO "Received SEQ: %x, Received ACK:%x\n",tcph->seq,tcph->ack_seq);
		strcpy(subnet,in->name);
	} else {
		printk(KERN_INFO "Input Device not directly connected!!!\n");
		printk(KERN_INFO "Received SEQ: %x, Received ACK:%x\n",tcph->seq,tcph->ack_seq);
		printk(KERN_INFO "Verifying SEQ and ACK...\n");
		csum_data[0]=tcph->seq;
		seq.half[0]=csum16(csum_data,CSUM_VAL);
		csum_data[0]=tcph->seq>>16;
		seq.half[1]=csum16(csum_data,CSUM_VAL);
		csum_data[0]=tcph->ack_seq;
		ack.half[0]=csum16(csum_data,CSUM_VAL);
		csum_data[0]=tcph->ack_seq>>16;
		ack.half[1]=csum16(csum_data,CSUM_VAL);
		tcph->seq=seq.full;
		tcph->ack_seq=ack.full;
		printk(KERN_INFO "Checksum results SEQ: %x, ACK:%x\n",tcph->seq,tcph->ack_seq);
	}
	neigh=ipv4_neigh_lookup(&iph->daddr,out);
	if(neigh!=NULL){			
		strcpy(subnet,out->name);
	}
	if(flags==10){
		
		if(tcph->ack_seq!=0){
			return -1;
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
		add_log(iph->saddr,iph->daddr,tcph->source,tcph->dest,tcph->seq,-2,-1,aux,-1,-1,flags,in->name,out->name,subnet);
		add_log(iph->saddr,iph->daddr,tcph->source,tcph->dest,-2,aux,-1,-1,tcph->seq,-2,10010,out->name,in->name,subnet);
	} else {
		if(tcph->fin==1 || tcph->syn==1){ //SYN or FIN
			t_size++;	
		}		
		curr_log=find_node(in->name,out->name,tcph->seq,tcph->ack_seq,flags);
		printk(KERN_INFO "PACKET SIZE:%d\n",t_size);
		if(t_size>0){
			if(curr_log==NULL){
				printk(KERN_INFO "Current packet not found.\n");
				curr_log=add_log(iph->saddr,iph->daddr,tcph->source,tcph->dest,tcph->seq,tcph->ack_seq,-1,-1,-1,-1,flags,in->name,out->name,subnet);
			} else {
				printk(KERN_INFO "Packet Found!!!\n");
			}
			if(flags==10010){
				aux=switch_order(tcph->seq);
				aux=aux+1;
				aux=switch_order(aux);
				next_log=find_node(out->name,in->name,aux,tcph->ack_seq,10000);
				if(next_log==NULL){
					next_log=add_log(iph->saddr,iph->daddr,tcph->source,tcph->dest,tcph->ack_seq,aux,-1,-1,curr_log->seq,curr_log->seq_ack,10000,out->name,in->name,subnet);
				} else {
					next_log->p_seq=curr_log->seq;
					next_log->p_seq_ack=curr_log->seq_ack;
				}
				curr_log->ack_recv=1;
				curr_log->seq=tcph->seq;
				curr_log->n_seq=curr_log->seq_ack;
				curr_log->n_seq_ack=aux;
				prev_log=find_node(out->name,in->name,curr_log->p_seq,curr_log->p_seq_ack,10);
				if(prev_log!=NULL){
					printk(KERN_INFO "Syn information found. Updating...\n");
				} else {
					printk(KERN_INFO "Syn info not found.\n");
				}
			} else { 
				if(tcph->psh==1){
					curr_log->ack_recv=1;	
				}
				aux=switch_order(tcph->seq);
				aux=aux+t_size;
				aux=switch_order(aux);
				next_log=find_node(out->name,in->name,aux,tcph->ack_seq,10000);
				if(next_log==NULL){
					add_log(iph->saddr,iph->daddr,tcph->source,tcph->dest,tcph->ack_seq,aux,-1,-1,curr_log->seq,curr_log->seq_ack,10000,out->name,in->name,subnet);
				} else {
					next_log->p_seq=curr_log->seq;
					next_log->p_seq_ack=curr_log->seq_ack;
				}
				curr_log->n_seq=tcph->ack_seq;
				curr_log->n_seq_ack=aux;
			}
		} else {
			if(curr_log==NULL){
				return -1;
			}
			if(tcph->ack==1){
				curr_log->ack_recv=1;
			}
		}
	}

	printk(KERN_INFO "SUBNET:%s\n",curr_log->subnet);
	if(strcmp(subnet,out->name)!=0){
		printk(KERN_INFO "Input Device not directly connected!!!\n");
		printk(KERN_INFO "Executing Checksum SEQ and ACK...\n");
		printk(KERN_INFO "Current SEQ: %x, ACK:%x\n",tcph->seq,tcph->ack_seq);
		csum_data[0]=tcph->seq;
		seq.half[0]=csum16(csum_data,CSUM_VAL);
		csum_data[0]=tcph->seq>>16;
		seq.half[1]=csum16(csum_data,CSUM_VAL);
		csum_data[0]=tcph->ack_seq;
		ack.half[0]=csum16(csum_data,CSUM_VAL);
		csum_data[0]=tcph->ack_seq>>16;
		ack.half[1]=csum16(csum_data,CSUM_VAL);
		tcph->seq=seq.full;
		tcph->ack_seq=ack.full;
		printk(KERN_INFO "Checksum results SEQ: %x, ACK:%x\n",tcph->seq,tcph->ack_seq);
	} else {
		printk(KERN_INFO "Output Device directly connected!!!\n");
		printk(KERN_INFO "Sending SEQ: %x, Sending ACK:%x\n",tcph->seq,tcph->ack_seq);
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

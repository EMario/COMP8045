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

struct node { //Linked list which will allow us to keep track of the packets
	uint32_t src_ip;
	uint16_t src_port;
	uint32_t curr_in_seq;
	uint32_t curr_out_seq;
	uint32_t next_in_seq;
	uint32_t next_out_seq;
	int flag;	//Contains current flag of the packet, so that we can know when syn/ack or fin/ack happens
	short int mode; //if the node is expecting an answer value is 1
	short int del;
	struct node* next;
};

struct node* head=NULL;
struct node* curr=NULL;
struct nf_hook_ops nfho;
char *src_ip,*dst_ip,*in_dev,*out_dev;
uint32_t src,dst;

module_param(in_dev,charp,0000);
MODULE_PARM_DESC(in,"Inside Network");
module_param(out_dev,charp,0000);
MODULE_PARM_DESC(out,"Outside Network");
module_param(src_ip,charp,0000);
MODULE_PARM_DESC(src_ip,"Source IP");
module_param(dst_ip,charp,0000);
MODULE_PARM_DESC(dst_ip,"Destination IP");

void add_node(uint32_t src_ip,uint16_t src_port, uint32_t seq,uint32_t ack,short int in,int flag){
	//Linked list node starter, it's created when a SYN packet comes through
	struct node *new_node = (struct node*) vmalloc (sizeof(struct node));
	new_node->src_ip=src_ip;
	new_node->src_port=src_port;
	if(in==true){ //if packet comes from our own network the inside sequence number is the SEQ
		new_node->curr_in_seq=seq;
		new_node->next_in_seq=seq+1;
		new_node->curr_out_seq=ack;
		new_node->next_out_seq=ack;
	} else { //if packet comes from an outside network the outside sequence number is the SEQ
		new_node->curr_out_seq=seq;
		new_node->next_out_seq=seq+1;
		new_node->curr_in_seq=ack;
		new_node->next_in_seq=ack;
	}
	new_node->flag=flag;
	new_node->mode=0; //0 sending, 1 receiving
	new_node->del=0; //deletion flag
	new_node->next=head;
	head=new_node;
}

struct node* find_node(uint32_t src_ip, uint16_t src_port){
	struct node* curr = head;
	if(head == NULL){
		return NULL;
	}

	while (curr->src_ip!=src_ip && curr->src_port!=src_port){
		if(curr->next == NULL){
			return NULL;
		} else {
			curr=curr->next;
		}
	}
	if(curr->src_ip==src_ip && curr->src_port==src_port){
		return curr;
	} else{
		return NULL;
	}
}

void update_node(uint32_t src_ip,uint16_t src_port, uint32_t seq,uint32_t ack,uint32_t new_seq,uint32_t new_ack,short int in){
	struct node* curr = find_node(src_ip, src_port);
	if(curr!=NULL){
		if(in==true){ //if packet comes from our own network the inside sequence number is the SEQ
			curr->curr_in_seq=seq;
			curr->next_in_seq=new_seq;
			curr->curr_out_seq=ack;
			curr->next_out_seq=new_ack;
		} else { //if packet comes from an outside network the outside sequence number is the SEQ
			curr->curr_out_seq=seq;
			curr->next_out_seq=new_seq;
			curr->curr_in_seq=ack;
			curr->next_in_seq=new_ack;
		}	
	}
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

void erase_nodes(uint32_t src_ip, uint16_t src_port){
	struct node *curr = head;
	struct node *previous = NULL;
	if(head == NULL){
		printk(KERN_INFO "Nothing to delete.\n");
		return;
	}

	while (curr!=NULL){
		previous = curr;
		curr = curr->next;
		vfree(previous);
	}
	printk(KERN_INFO "Deleted all entries.");
}

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
	struct node* curr;
	int flags=0,size;
	/*union {
		uint32_t u32;
		uint8_t arr[4];
	} x,y;*/
	iph = (struct iphdr*)skb_network_header(skb);
	if(iph->protocol==IPPROTO_TCP){
		printk(KERN_INFO "Received a TCP packet!!!\n");
		tcph = (struct tcphdr*)skb_transport_header(skb);
		flags=(int) tcph->urg * 100000;
		flags+=(int) tcph->ack * 10000;
		flags+=(int) tcph->psh * 1000;
		flags+=(int) tcph->rst * 100;
		flags+=(int) tcph->syn * 10;
		flags+=(int) tcph->fin * 1;
		if(in->name==in_dev){
			
			if(flags==000010){ //SYN from the host that initiates the transmission
				add_node(iph->saddr, tcph->source,tcph->seq,tcph->ack,0,flags);
				curr = find_node(iph->saddr, tcph->source);
				printk(KERN_INFO "SEQ=%x, NEXT_SEQ=%x, ACK= %x, NEXT_ACK=%x\n",curr->curr_in_seq,curr->next_in_seq, curr->curr_in_seq,curr->curr_out_seq);
			} else if(flags==010010){ //SYN/ACK from the host that responds
				curr = find_node(iph->daddr, tcph->dest);
				printk(KERN_INFO "SEQ=%x, NEXT_SEQ=%x, ACK= %x, NEXT_ACK=%x\n",curr->curr_in_seq,curr->next_in_seq, curr->curr_in_seq,curr->curr_out_seq);
				curr = find_node(iph->daddr, tcph->dest);
				update_node(iph->saddr, tcph->source,tcph->ack,tcph->seq,tcph->ack,tcph->seq+1,0);
			} else if(flags==000001){ //FIN  from the host that initiates the transmission
				curr = find_node(iph->daddr, tcph->dest);
				update_node(iph->saddr, tcph->source,tcph->seq,tcph->ack,tcph->seq+1,tcph->ack,0);
				printk(KERN_INFO "SEQ=%x, NEXT_SEQ=%x, ACK= %x, NEXT_ACK=%x\n",curr->curr_in_seq,curr->next_in_seq, curr->curr_in_seq,curr->curr_out_seq);
			} else if(flags==010001){ //FIN/ACK from the host that responds
				curr = find_node(iph->daddr, tcph->dest);
				update_node(iph->saddr, tcph->source,tcph->ack,tcph->seq,tcph->ack,tcph->seq+1,0);
				printk(KERN_INFO "SEQ=%x, NEXT_SEQ=%x, ACK= %x, NEXT_ACK=%x\n",curr->curr_in_seq,curr->next_in_seq, curr->curr_in_seq,curr->curr_out_seq);
			} else {
				size=sizeof(tcph) + (tcph->doff * 4);
				printk(KERN_INFO "SIZE=%d\n",size);
			}
		} 
		if(in->name==out_dev){
			if(flags==000010){ //SYN from the host that responds
				//if() //Check if ack contains valid id if so
				add_node(iph->saddr, tcph->source,tcph->seq,tcph->ack,0,flags);
				curr = find_node(iph->saddr, tcph->source);
				printk(KERN_INFO "SEQ=%x, NEXT_SEQ=%x, ACK= %x, NEXT_ACK=%x\n",curr->curr_in_seq,curr->next_in_seq, curr->curr_in_seq,curr->curr_out_seq);
				//otherwise drop
			} else if(flags==010010){ //SYN/ACK from the host that initiates the transmission
				curr = find_node(iph->daddr, tcph->dest);
				update_node(iph->saddr, tcph->source,tcph->seq,tcph->ack,tcph->seq+1,tcph->ack,0);
				printk(KERN_INFO "SEQ=%x, NEXT_SEQ=%x, ACK= %x, NEXT_ACK=%x\n",curr->curr_in_seq,curr->next_in_seq, curr->curr_in_seq,curr->curr_out_seq);
			} else if(flags==000001){ //FIN  from the host that responds
				curr = find_node(iph->daddr, tcph->dest);
				update_node(iph->saddr, tcph->source,tcph->ack,tcph->seq,tcph->ack+1,tcph->seq,0);
				printk(KERN_INFO "SEQ=%x, NEXT_SEQ=%x, ACK= %x, NEXT_ACK=%x\n",curr->curr_in_seq,curr->next_in_seq, curr->curr_in_seq,curr->curr_out_seq);
			} else if(flags==010001){ //FIN/ACK from the host that initiates the transmission
				curr = find_node(iph->daddr, tcph->dest);
				update_node(iph->saddr, tcph->source,tcph->seq,tcph->ack,tcph->seq,tcph->ack+1,0);
				printk(KERN_INFO "SEQ=%x, NEXT_SEQ=%x, ACK= %x, NEXT_ACK=%x\n",curr->curr_in_seq,curr->next_in_seq, curr->curr_in_seq,curr->curr_out_seq);				
			} else {
				size=sizeof(tcph) + (tcph->doff * 4);
				printk(KERN_INFO "SIZE=%d\n",size);
			}
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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>

#include <linux/vmalloc.h>
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <linux/netfilter.h>
#include <asm/uaccess.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netfilter_ipv4.h>		// has the netfilter hook's structure

#include "kernelfw.h"     

#define MAX_RULES 			100
#define RULE_DOES_NOT_MATCH 1
#define RULE_MATCHES      	0
#define UID_MAX        		256

//#define __KERNEL__
//#define MODULE

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("minifw Loadable Kernel Module");
MODULE_AUTHOR("Oscar");

static struct 			proc_dir_entry *proc_entry;
static my_iptable 		minifw_rules_table[MAX_RULES];
static my_iptable 		*my_ipt;
static struct 			nf_hook_ops nfho_in;
static struct 			nf_hook_ops nfho_out;
static unsigned char 	allowed_users[UID_MAX];

static unsigned char	num_of_rules; //规则总数
static unsigned int 	rule_index;
static unsigned int 	next_rule_ctr;

unsigned int minifw_inbound_filter(void* hook, struct sk_buff *skb, const struct nf_hook_state* hs);
unsigned int minifw_outbound_filter(void* hook, struct sk_buff *skb, const struct nf_hook_state* hs);
ssize_t minifw_write(struct file *filp, const char __user *buff, size_t len, loff_t *data);
ssize_t minifw_read(struct file *filp, char __user *buff, size_t len, loff_t *data);

int Check_Rule(struct sk_buff *skb, my_iptable *my_ipt);
int Check_IP(const unsigned char *ip_addr1, const unsigned char *ip_addr2, const char *net_mask);
int Check_Protocol(const unsigned short protocol1, const unsigned short protocol2);
int Check_Port(const unsigned short port1, const unsigned short port2);
int Check_Permission(const my_iptable *my_ipt);
int Delete_Rule(const my_iptable *my_ipt);


int init_minifw_read_write_module(void) {
	int ret = 0;
	my_ipt = (my_iptable *)vmalloc(sizeof(my_iptable)); // vmalloc 是内核的内存申请函数
	//printk(KERN_INFO "going to read my_iptable rules\n");
	if(!my_ipt)														// 检查null
		ret = -ENOMEM;
	else {
		memset((char *)my_ipt, 0, sizeof(my_iptable));				// 初始化为0
		memset(minifw_rules_table, 0, sizeof(minifw_rules_table));
		static struct proc_ops pf={
			.proc_read = minifw_read,
			.proc_write = minifw_write,
			// .owner = THIS_MODULE,
		};
		proc_entry = proc_create("minifw", 0646, NULL, &pf);		// rw-r--rw-, the owner of this proc would have read/write permissions
		if(proc_entry == NULL) {
			ret = -ENOMEM;
			vfree(my_ipt);
			printk(KERN_INFO "minifw: couldn't create proc\n");
		}		
		else {
			printk(KERN_INFO "minifw: minifw proc succesfully registered\n");
			rule_index = 0;
			next_rule_ctr = 0;
			num_of_rules = 0;
			memset(allowed_users, 0, UID_MAX * sizeof(unsigned char));
			allowed_users[0] = 1;      				// 超级用户默认有权限
			// proc_entry->proc_fops->read = minifw_read;
			// proc_entry->proc_fops->write = minifw_write;
			// proc_entry->owner = THIS_MODULE;
			printk(KERN_INFO "minifw: minifw read_write module loaded successfully\n");	
		}
	}
	return 0;
}

int init_rule_match_module(void) {
	nfho_in.hook		= minifw_inbound_filter;		// other->local的数据包过滤
	nfho_in.hooknum 	= NF_INET_LOCAL_IN;				// 设置钩子函数触发的节点
	nfho_in.pf			= PF_INET;						
	nfho_in.priority 	= NF_IP_PRI_FIRST;				// 设置钩子函数优先级
	nf_register_net_hook(&init_net, &nfho_in);
	
	nfho_out.hook		= minifw_outbound_filter;		// local->other host的数据包过滤
	nfho_out.hooknum	= NF_INET_LOCAL_OUT;
	nfho_out.pf			= PF_INET;
	nfho_out.priority	= NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfho_out);

	printk(KERN_INFO "minifw: rule match module loaded\n");
	return 0;	
}	

int my_init_module(void) {
	init_minifw_read_write_module();
	init_rule_match_module();
	return 0;
}

//用户态程序与内核程序交互的入口，这是write响应，用于修改内核程序全局变量的值来更改防火墙规则
//更好的写法是将防火墙规则制定成某个文件，但我懒得整了
ssize_t minifw_write(struct file *filp, const char __user *buff, size_t len, loff_t *data) {
	int rules_remaining = MAX_RULES - rule_index;			// 计算剩余的规则数
	int num = len / sizeof(my_iptable);						// 添加的规则数	
	memset(my_ipt, 0, sizeof(my_iptable));					// my_ipt填充为0 

	if (num > rules_remaining) {							// 剩余规则数不足
		printk(KERN_INFO "minifw: minifw_table is out of memory. Will exit now..\n");
		return -ENOSPC;
	} 
	
	if (copy_from_user(my_ipt, buff, len)) {				// 从buff中复制进入my_ipt中
		printk(KERN_INFO "Sorry, reading the user-data from /proc failed");
		return -EFAULT;
	}					
	//printk(KERN_INFO "\ncopied the rule from user \nrules_remaining: %d, num: %d, len: %ld\n", rules_remaining, num, len);

	// 检查权限，权限不足无法修改防火墙规则
	if(Check_Permission(my_ipt)) {
		printk(KERN_INFO "minifw: %d UID doesn't have sufficient rights to access minifw\n", current_uid().val);
		return -EFAULT;	
	}
	
	// 如果选择删除规则
	if(my_ipt->action == DELETE) {
		if (!Delete_Rule(my_ipt))
			printk(KERN_INFO "minifw: minifw has deleted the rule %u\n", my_ipt->rule_index);		
		else
			printk(KERN_INFO "minifw: minifw couldn't find your rule to delete\n");		
		return 0;
	}
	// 只有超级用户可以修改其他用户的权限
	else if(my_ipt->action == ALLOW_ACCESS) {
		if (current_uid().val != 0)
			printk(KERN_INFO "minifw: only the super user can change the access permissions\n");
		else {
			printk(KERN_INFO "minifw: UID %d gained access rights\n", my_ipt->uid);
			allowed_users[(my_ipt->uid % UID_MAX)] = 1;	
			//printk(KERN_INFO "allowed_users[%d] = 1", my_ipt->uid % UID_MAX);
		}
		return 0;
	}
	else if(my_ipt->action == REMOVE_ACCESS) {
		if (current_uid().val != 0)
			printk(KERN_INFO "minifw: only the super user can change the access permissions\n");
		else {			
			printk(KERN_INFO "minifw: UID %d lost access rights\n", my_ipt->uid);
			if (my_ipt->uid == 0)		// 超级用户不能不给自己权限
				return 0;
			allowed_users[(my_ipt->uid % UID_MAX)] = 0;
		}
		return 0;
	}

	printk(KERN_INFO "my_ipt hook number: %u \n", my_ipt->hook_entry);
	memcpy(minifw_rules_table + rule_index, my_ipt, sizeof(my_iptable));
	//printk(KERN_INFO "rule written. rule_index: %d, num_of_rules: %d", rule_index+1, num_of_rules+1);
	rule_index ++;
	num_of_rules ++;
	
	return len;	
}

ssize_t minifw_read(struct file *filp, char __user *buff, size_t len, loff_t *data) {
	unsigned int num = len / sizeof(my_iptable);
	printk(KERN_INFO "minifw: Total number of rules: %d\n", num_of_rules);
	unsigned char mmin = num > num_of_rules ? num_of_rules : num;
	printk(KERN_INFO "minifw: Total number of rules printed: %d\n", mmin);	
	if (copy_to_user(buff, minifw_rules_table, mmin * sizeof(my_iptable))) {				// 复制进入buff中
		printk(KERN_INFO "Sorry, reading the user-data from /proc failed");
		return -EFAULT;
	}
	if (copy_to_user(buff + 100 * sizeof(my_iptable), &mmin, 1)) {				// 复制进入buff中
		printk(KERN_INFO "Sorry, reading the user-data from /proc failed");
		return -EFAULT;
	}
	return mmin * sizeof(my_iptable);
}

// inbound packets的钩子函数，按规则过滤数据包
unsigned int minifw_inbound_filter(void* hook, struct sk_buff *skb, const struct nf_hook_state* hs)
{
	int index = 0;
	int action = 0;
	for(index = 0; index < num_of_rules; index ++) {						// 遍历查看是否符合规则，符合且BLOCK直接抛弃
		if(minifw_rules_table[index].hook_entry == NF_INET_LOCAL_IN) 
		{
			action = Check_Rule(skb, &minifw_rules_table[index]);
			if(!action)	{
				if (minifw_rules_table[index].action == BLOCK)
					return NF_DROP;
				else
					return NF_ACCEPT;
			}
		}
	}
	return NF_ACCEPT;
}

// outbound packets的钩子函数，按规则过滤数据包
unsigned int minifw_outbound_filter(void* hook, struct sk_buff *skb, const struct nf_hook_state* hs)
{
	int index = 0;
	int action = 0;	
	for(index = 0; index < num_of_rules; index ++) {
		if(minifw_rules_table[index].hook_entry == NF_INET_LOCAL_OUT) {
			action = Check_Rule(skb, &minifw_rules_table[index]);
			if(!action) {				
				if (minifw_rules_table[index].action == BLOCK)
					return NF_DROP;
				else
					return NF_ACCEPT;
			}
		}	
	}
	return NF_ACCEPT;
}

// 检查权限
int Check_Permission(const my_iptable *my_ipt) {	
	//printk(KERN_INFO "minifw: Checking the access right of UID %d, Index: %d\n", my_ipt->uid, my_ipt->uid % UID_MAX);
	if (allowed_users[(current_uid().val % UID_MAX)]) {	
		printk(KERN_INFO "minifw: UID %d is allowed to access minifw\n", my_ipt->uid);
		return 0;
	}
	else
		return 1;
	return 0;
}

// delete a rule from minifw policy set
int Delete_Rule(const my_iptable *my_ipt) {
	unsigned int index = my_ipt->rule_index - 1;
	if (index + 1 > num_of_rules) {
		printk(KERN_INFO "minifw: The index for the given rule is out of bounds, Delete operation unsuccessful\n");
		return 1;
	}
	memset(&(minifw_rules_table[index]), 0 , sizeof(my_iptable));	// 置0
		
	if (index == num_of_rules - 1) { 								// 如果是最后一条
		--num_of_rules;												
		--rule_index;	
	}	
	else {															// 如果不是最后一条，数组向前移动 
		for(; index < num_of_rules-1; index++)
			minifw_rules_table[index] = minifw_rules_table[index + 1];		
		num_of_rules --;
		rule_index --;
	}
	return 0;
}

// 检查数据包skb是否符合规则my_ipt
int Check_Rule(struct sk_buff *skb, my_iptable *my_ipt) {
	//struct ethhdr *eth_h 	=	eth_hdr(skb);					
	struct iphdr *ip_header 		= 	ip_hdr(skb);		// defined in /lib.../linux/ip.h, returns iphdr as (struct iphdr*)skb_network_header(skb)
	struct tcphdr *tcp_header 		=	tcp_hdr(skb);		// in /lib.../tcp.h, 	returns tcphdr as (struct tcphdr*)skb_transport_header(skb)
	struct udphdr *udp_header 		=	udp_hdr(skb);		// in /lib.../udp.h, 	returns udphdr as (struct udphdr*)skb_transport_header(skb)
	// struct icmphdr *icmp_header 	=	icmp_hdr(skb);		// in /lib/.../icmp.h, 	returns icmphdr as (struct icmphdr*)skb_transport_header(skb)
	
	// 如果规则是限制source ip
	if((my_ipt->ip_rule.bitmask & IS_SIP) == IS_SIP) {
		if(!Check_IP((unsigned char *)(&ip_header->saddr), my_ipt->ip_rule.sip, my_ipt->ip_rule.smask))
		{}
		else
			return RULE_DOES_NOT_MATCH;
	}
	// 如果规则是限制dest ip
	if ((my_ipt->ip_rule.bitmask & IS_DIP ) == IS_DIP) {
		if(!Check_IP((unsigned char *)(&ip_header->daddr), my_ipt->ip_rule.dip, my_ipt->ip_rule.dmask))
		{}
		else
			return RULE_DOES_NOT_MATCH;
	}	

	// 是否与规则规定的协议一致
	if ((my_ipt->ip_rule.bitmask & IP_TYPE_PACKET ) == IP_TYPE_PACKET)		// check the type of protocol if the packet is of type IP
	{		
		if (!Check_Protocol(ip_header->protocol, my_ipt->ip_rule.proto))	// shall return success for ICMP protocol too as it is saved in my_ipt->ip_rule.proto
		{
			if(ip_header->protocol == ICMP_PROTOCOL)
				return RULE_MATCHES;
		}
		else
			return RULE_DOES_NOT_MATCH;
	}
	
	// 检查tcp/udp协议的源端口号是否符合要求
	if ((my_ipt->port_rule.bitmask & IS_SPORT) == IS_SPORT)	{
		if (!Check_Port(tcp_header->source, my_ipt->port_rule.sport))
		{}
		else if (!Check_Port(udp_header->source, my_ipt->port_rule.sport))
		{}
		// else if (!Check_Port(icmp_header->source, my_ipt->port_rule.sport, IS_SPORT))	// icmp header doesn't have a source/dest port
		// {}
		else
			return RULE_DOES_NOT_MATCH;  
	}
	// 检查tcp/udp协议的目的端口号是否符合要求
	if ((my_ipt->port_rule.bitmask & IS_DPORT) == IS_DPORT) {
		if (!Check_Port(tcp_header->dest, my_ipt->port_rule.dport))
		{printk(KERN_INFO "Destination port checking\n");}
		else if (!Check_Port(udp_header->dest, my_ipt->port_rule.dport))
		{}
		// else if (!Check_Port(icmp_header->source, my_ipt->port_rule.sport, IS_DPORT))
		// {}
		else
			return RULE_DOES_NOT_MATCH;  
	}

	my_ipt->packet_count++;			// increase the packet count under my_ipt and return RULE_MATCHES if the fields were properly set
	return RULE_MATCHES;
}

int Check_IP(const unsigned char *ip_addr1, const unsigned char *ip_addr2, const char *net_mask) {
	int action = RULE_DOES_NOT_MATCH;
	unsigned char accept_all_ip[] = {0x00,0x00,0x00,0x00};
	int *ip1, *ip2, *netmask;
	ip1 = (int *)ip_addr1,
	ip2 = (int *)ip_addr2;
	netmask = (int *)net_mask;
	// printk(KERN_INFO "ip1:%u.%u.%u.%u,ip2:%u.%u.%u.%u,netmask:%u.%u.%u.%u\n", (*ip1)/256/256/256, (*ip1)/256/256%256, (*ip1)/256%256, (*ip1)%256\
	// , (*ip2)/256/256/256, (*ip2)/256/256%256, (*ip2)/256%256, (*ip2)%256\
	// , (*netmask)/256/256/256, (*netmask)/256/256%256, (*netmask)/256%256, (*netmask)%256);
	do {
		if (!memcmp(ip1, ip2, IP_ADDR_LEN))	{					// check if the host-ip address is the same
			action = RULE_MATCHES;	
			break;
		}
		else {
			if(!memcmp(accept_all_ip, net_mask, IP_ADDR_LEN)) { 		// check if the subnet mask is 0.0.0.0, if so accept the packets
				action = RULE_MATCHES;
				break;
			}												
			else {				
				if(((*ip1)&(*netmask)) == ((*ip2)&(*netmask))) {   	// check if the net-address (host & mask) is same
					action = RULE_MATCHES;								
					break;
				}
				else {
					action = RULE_DOES_NOT_MATCH;							
					break;
				}
			}
		}
	}
	while(0)	;
	return action;
}			

int Check_Protocol(const unsigned short protocol1, const unsigned short protocol2) {
	int action = RULE_DOES_NOT_MATCH;
	do {		
		if(protocol2 == ALL_PROTOCOLS) {
			action = RULE_MATCHES;		
			break;
		}			
		else if(protocol1 == protocol2) {
			action = RULE_MATCHES;		
			break;
		}			
		else {
			action = RULE_DOES_NOT_MATCH;	
			break;
		}
	}
	while(0);
 	return action;				
}

int Check_Port(const unsigned short port1, const unsigned short port2) {
	int action = RULE_DOES_NOT_MATCH;
	int newport1 = port1 % 256 * 256 + port1 / 256;
	printk(KERN_INFO "port1:%d, port2:%d\n", newport1, port2);
	do {
		if(newport1 == port2) {
			printk(KERN_INFO "Destination port matches\n");
			action = RULE_MATCHES;					
			break;
		}
	else { 
		action = RULE_DOES_NOT_MATCH;			
		break;
		}
	}
	while(0);
	return action;
}

void cleanup_minifw_read_write_module(void) {
	remove_proc_entry("minifw", NULL);
	vfree(my_ipt);
	printk(KERN_INFO "minifw: minifw read_write module unloaded successfully\n");
}

void cleanup_rule_match_module(void) {
	nf_unregister_net_hook(&init_net, &nfho_in);
	nf_unregister_net_hook(&init_net, &nfho_out);
	printk(KERN_INFO "minifw: minifw rule match module unloaded\n");
}

void my_cleanup_module(void) {
	cleanup_minifw_read_write_module();
	cleanup_rule_match_module();
}

module_init(my_init_module);
module_exit(my_cleanup_module);

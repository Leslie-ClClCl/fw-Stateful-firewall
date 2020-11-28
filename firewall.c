#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/udp.h>
#include <linux/time.h>

#define DEV_SZ 0x2000

#define FIN  0x01
#define SYN  0x02
#define RST  0x04
#define PUSH 0x08
#define ACK  0x10
#define URG  0x20
#define ECE  0x40
#define CWR  0x80

#define REFRESH_STAT    1
#define SET_LOCAL_IP    2
#define SET_PUB_IP      3
#define TIME_OUT        4
#define DEFAULT_STRATEGY 5

#define DEFAULT_PERMIT 1
#define DEFAULT_REJECT 0

#define multiple_32 2654435769
#define multiple_16 40503
#define multiple_8  158
#define bufSize     0x10000
typedef unsigned long long ULL;

int dev_opened;
unsigned char dev_mem[DEV_SZ];
unsigned rules_num;
unsigned audit_num;
struct cdev cdev;
dev_t devno;
static struct nf_hook_ops nfho_out, nfho_in, nfho_nat;
int defaultStrategy;

unsigned int local_ip;
unsigned int pub_ip;
time_t ttl;

struct rule {
    unsigned int    saddr;    // source IP address
    unsigned int    daddr;    // dest IP address
    unsigned char   smask;    // source IP mask
    unsigned char   dmask;    // dest IP mask
    unsigned int    source;    // source port
    unsigned int    dest;    // dest port
    unsigned char   protocol;    // protocol

    unsigned char   audit;        // whether to log information
    unsigned char   action;    // permit or reject
} rules[500];

struct Quintuple {
    unsigned int  saddr;    // source IP address
    unsigned int  daddr;    // dest IP address
    unsigned int  source;    // source port
    unsigned int  dest;    // dest port
    unsigned char protocol;    // protocol
};

struct status {
    unsigned int saddr;
    unsigned int daddr;
    unsigned int source;
    unsigned int dest;
    // unsigned int seq;
    // unsigned int ack;
    // unsigned char stat;
    time_t last_t;
    struct status *next;
} statList[bufSize];

struct nat {
    unsigned int ip_loc;
    unsigned int ip_pub;
    unsigned short port_loc;
    unsigned short port_pub;
    struct nat *next;
} natList[bufSize];


// Declarations of my own operation functions
int     open(struct inode *, struct file *);
int     release(struct inode *, struct file *);
ssize_t read(struct file *, char __user *, size_t, loff_t *);
ssize_t write(struct file *, const char __user *, size_t, loff_t *);
loff_t  llseek(struct file *, loff_t, int);
long    ioctl(struct file *filp, unsigned int cmd, unsigned long arg);

// Declarations of all the functions
void initStatHashTable(void);
void initNAThashTable9(void);
ULL getQuinHash(struct Quintuple *q);
ULL getIPhash(unsigned int ip, unsigned short port);
struct status *matchStatus(struct Quintuple *q);
struct nat *matchNat(unsigned int ip, unsigned short port);

void addStatus(struct Quintuple *q);
void delStatus(struct status *prev, struct status *cur);
void addNat(struct nat *n);
void delNat(struct nat *prev, struct nat *cur); // TO DO

int getQuintuple(struct sk_buff *skb, struct Quintuple *info);
int matchIPaddr(unsigned int addr1, unsigned int addr2, unsigned char shortmask);
unsigned int regularMatcher(struct Quintuple *pkt_info);
unsigned int net_filter_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
unsigned int net_filter_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
unsigned int net_nat(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static int __init initFirewall(void);
static void __exit exitFirewall(void);
unsigned char getTCPflags(struct sk_buff *skb, unsigned char FLAG);
int isLocalIP(unsigned int ip);
void UpdateChecksum(struct sk_buff *skb);
int needNAT(struct sk_buff *skb);
// Associating function entry points
static const struct file_operations fops = {
  .owner = THIS_MODULE,
  .open = open,
  .release = release,
  .read = read,
  .write = write,
  // .llseek = llseek,
    .unlocked_ioctl = ioctl,
};


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                      Functions for device operations              //////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int open(struct inode *inode, struct file *filp) {
    // To open the device
    if (dev_opened) {
        printk("The device is occupied!\n");
        return -EBUSY;
    }
    dev_opened++;
    filp->private_data = dev_mem;
    printk("The device is opened successfully!\n");
    return 0;
}
//
int release(struct inode *inode, struct file *filp) {
    // To release the device
    dev_opened--;
    printk("The device has been released!\n");
    return 0;
}
//
ssize_t read(struct file * filp, char __user *buffer, size_t size, loff_t *offset) {
    // Read from the device
    // copy the status to the user's space
    int i = 0;
    ssize_t count = 0;
    size_t len = sizeof(struct status);
    for (i = 0; i < bufSize && count*len < size; i++) {
        struct status *head = statList[i].next;
        while (head && count*len < size) {
            copy_to_user(buffer+count*len, head, len);
            count++;
            head = head->next;
        }
    }
    return count;
}
ssize_t write(struct file *filp, const char __user *buffer, size_t size, loff_t *offset) {
    // To write to the device
    printk("Write begin~\n");
    
    if (copy_from_user((unsigned char *)rules+rules_num*sizeof(struct rule), buffer, size)) {
        printk("Fail to copy from user\n");
        return 0;
    }
    printk("Copy done!\n");
    
    rules_num += size / sizeof(struct rule);
    return 1;
}
//
long ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
	if (cmd == REFRESH_STAT) {
        // refresh the status list, and delete timeup status
        struct timeval tv;
        int i = 0;
        do_gettimeofday(&tv);
        for (i = 0; i < bufSize; i++) {
            struct status *s = &statList[i];
            while (s != NULL && s->next != NULL) {
                // check if time's up
                if (s->next->last_t + ttl < tv.tv_sec) {
                    delStatus(s, s->next);
                }
                s = s->next;
            }
        }
        return 0;
	} else if (cmd == SET_LOCAL_IP) {
        local_ip = arg;
        return 0;
    } else if (cmd == SET_PUB_IP) {
        printk("WAN has changed to %u\n", arg);
        pub_ip = arg;
        return 0;
    } else if (cmd == TIME_OUT) {
        ttl = arg;
    } else if (cmd == DEFAULT_STRATEGY) {
        defaultStrategy = arg;
        printk("arg is %d. ds change to %d", arg, defaultStrategy);
    }
	return -EINVAL;
}
//
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                             functional funcs              //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int getQuintuple(struct sk_buff *skb, struct Quintuple *info) {
    // get info from IP packet
    struct iphdr *iph;
    if (skb == NULL  || info == NULL)
        return -1;

    iph = ip_hdr(skb);

    if (iph == NULL)
        return -1;
    
    info->saddr = iph->saddr;    // get source IP address
    info->daddr = iph->daddr;    // get dest IOP address
    info->protocol = iph->protocol;    // get protocol's num

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + iph->ihl*4;
        if (tcph == NULL)
            return -1;
        info->source = ntohs(tcph->source);    // get source TCP port
        info->dest = ntohs(tcph->dest);        // get dest TCP port
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)iph + iph->ihl*4;
        if (udph == NULL)
            return -1;
        info->source = ntohs(udph->source);    // get source UDP port
        info->dest = ntohs(udph->dest);        // get dest UDP port
    } else if (iph->protocol == IPPROTO_ICMP) {
        ;
    }
    return 0;
}
//
unsigned char getTCPflags(struct sk_buff *skb, unsigned char FLAG) {
    struct tcphdr *tcph = tcp_hdr(skb);
    unsigned char flag;
    if (tcph == NULL)
        return 0;
    flag = *((unsigned char *)tcph + 13);
    // TO DO verify the correctness
    return flag & FLAG;
}
//
int matchIPaddr(unsigned int addr1, unsigned int addr2, unsigned char shortmask) {
    // match the mask
    unsigned mask = 0xffffffff;
    mask = mask >> (32-shortmask);
    return (addr1 & mask) == (addr2 & mask);
}
//
int needNAT(struct sk_buff *skb) {
    struct iphdr *iph = ip_hdr(skb);
    if (isLocalIP(iph->saddr) && !isLocalIP(iph->daddr))
        return 1;
    if (!isLocalIP(iph->saddr) && matchIPaddr(iph->daddr, pub_ip, 32))
        return 1;
    return 0;
}
//
unsigned int regularMatcher(struct Quintuple *pkt_info) {
    // to determine the action
    int i;
    if (pkt_info == NULL) {
        // printk("null ptr");
        return NF_DROP;
    }
    for (i = 0; i < rules_num; i++) {
        if (!matchIPaddr(pkt_info->saddr, rules[i].saddr, rules[i].smask) && rules[i].saddr != -1)
            continue;
        else if (!matchIPaddr(pkt_info->daddr, rules[i].daddr, rules[i].dmask) && rules[i].daddr != -1)
            continue;
        else if (rules[i].source != pkt_info->source && rules[i].source != -1)
            continue;
        else if (rules[i].dest != pkt_info->dest && rules[i].dest != -1)
            continue;
        if (rules[i].audit) {
            ((struct rule *)dev_mem)[audit_num].saddr = pkt_info->saddr;
            ((struct rule *)dev_mem)[audit_num].daddr = pkt_info->daddr;
            ((struct rule *)dev_mem)[audit_num].source = pkt_info->source;
            ((struct rule *)dev_mem)[audit_num].dest = pkt_info->dest;
            ((struct rule *)dev_mem)[audit_num].protocol = pkt_info->protocol;
        }
        // printk("%s\n", rules[i].action ? "Permit" : "Reject");
        return rules[i].action;
    }
    // printk("Reject\n");
    return NF_DROP;
}
//
int isLocalIP(unsigned int ip) {
    if (matchIPaddr(ip, 10, 8)) {
        return 1;
    }
    if (matchIPaddr(ip, 4268, 16)){
        return 1;
    }
    if (matchIPaddr(ip, 43200, 16)) {
        return 1;
    } 
    return 0;
}
//
void UpdateChecksum(struct sk_buff *skb) {
    struct iphdr *ip_header;

    ip_header = ip_hdr(skb);
    skb->ip_summed = CHECKSUM_NONE; //stop offloading
    skb->csum_valid = 0;
    ip_header->check = 0;
    ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);

    if ( (ip_header->protocol == IPPROTO_TCP) || (ip_header->protocol == IPPROTO_UDP) ) {
        if(skb_is_nonlinear(skb))
        skb_linearize(skb);  // very important.. You need this.

        if (ip_header->protocol == IPPROTO_TCP) {
            struct tcphdr *tcpHdr;
            unsigned int tcplen;

            tcpHdr = tcp_hdr(skb);
            skb->csum =0;
            tcplen = ntohs(ip_header->tot_len) - ip_header->ihl*4;
            tcpHdr->check = 0;
            tcpHdr->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr, csum_partial((char *)tcpHdr, tcplen, 0));
        } else if (ip_header->protocol == IPPROTO_UDP) {
            struct udphdr *udpHdr;
            unsigned int udplen;

            udpHdr = udp_hdr(skb);
            skb->csum =0;
            udplen = ntohs(ip_header->tot_len) - ip_header->ihl*4;
            udpHdr->check = 0;
            udpHdr->check = udp_v4_check(udplen,ip_header->saddr, ip_header->daddr,csum_partial((char *)udpHdr, udplen, 0));
        }
    }
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                          Net Filter Complement                       //
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void initStatHashTable(void) {
    int i = 0;
    for (i = 0; i < bufSize; i++) {
        statList[i].next = NULL;
    }
    return;
}
//
void initNAThashTable(void) {
    int i = 0;
    for (i = 0; i < bufSize; i++) {
        natList[i].next = NULL;
    }
    return;
}
ULL getQuinHash(struct Quintuple *q) {
    // get a quintuple's hash value
    ULL res = 0;
    res += (q->saddr * multiple_32);
    res += (q->daddr * multiple_32);
    res += (q->source * multiple_8);
    res += (q->dest * multiple_8);
    return res >> 48;
}
//
ULL getIPhash(unsigned int ip, unsigned short port) {
    // get a hash by ip and port
    ULL res = 0;
    res += (ip * multiple_32);
    res += (port * multiple_16);
    return res >> 48;
}
//
struct status *matchStatus(struct Quintuple *q) {
    // match the quintuple on the status list
    // if matched, return the pointer, else return null
    ULL hashValue = getQuinHash(q);
    struct status *head = statList[hashValue].next;
    while (head != NULL) {
        if (q->saddr == head->saddr && q->daddr == head->daddr && q->source == head->source && q->dest == head->dest) {
            // printk("status list matched!\n");
            return head;
        }
        head = head->next;
    }
    // printk("status list not matched!\n");
    return NULL;
}
//
struct nat *matchNat(unsigned int ip, unsigned short port) {
    ULL hashValue = getIPhash(ip, port);
    struct nat *head = natList[hashValue].next;
    while (head != NULL) {
        if (ip == head->ip_loc && port == head->port_loc)
            return head;
        else if (ip == head->ip_pub && port == head->port_pub)
            return head;
        head = head->next;
    }
    return NULL;
}
//
void addStatus(struct Quintuple *q) {
    // add a new status infomation onto the hash table
    ULL hashValue = getQuinHash(q);
    struct status *ptr = (struct status*)kmalloc(sizeof(struct status), GFP_KERNEL);
    struct timeval tv;
    struct status *head = NULL;
    do_gettimeofday(&tv);
    ptr->saddr = q->saddr;
    ptr->daddr = q->daddr;
    ptr->source = q->source;
    ptr->dest = q->dest;
    ptr->last_t = tv.tv_sec;
    ptr->next = NULL;
    
    head = &statList[hashValue];
    ptr->next = head->next;
    head->next = ptr;
    printk("status has added to the list\n");
    return;
}
//
void delStatus(struct status *prev, struct status *cur) {
    // Delete the stat pointed to by *cur
    if (prev == NULL || cur == NULL)
        return;
    prev->next = cur->next;
    kfree(cur);
    return;
}
//
void addNat(struct nat *n) {
    ULL hashValue1 = getIPhash(n->ip_loc, n->port_loc);
    ULL hashValue2 = getIPhash(n->ip_pub, n->port_pub);
    struct nat *ptr1 = (struct nat*)kmalloc(sizeof(struct nat), GFP_KERNEL);
    struct nat *ptr2 = (struct nat*)kmalloc(sizeof(struct nat), GFP_KERNEL);
    struct nat *head = NULL;
    ptr1->ip_loc = ptr2->ip_loc = n->ip_loc;
    ptr1->ip_pub = ptr2->ip_pub = n->ip_pub;
    ptr1->port_loc = ptr2->port_loc = n->port_loc;
    ptr1->port_pub = ptr2->port_pub = n->port_pub;
    ptr1->next = ptr2->next = NULL;

    head = &natList[hashValue1];
    ptr1->next = head->next;
    head->next = ptr1;
    head = &natList[hashValue2];
    ptr2->next = head->next;
    head->next = ptr2;
    return;
}
//
void delNat(struct nat *prev, struct nat *cur) {
    if (prev == NULL || cur == NULL)
        return;
    prev->next = cur->next;
    kfree(cur);
    return;
}

void NATtransfer(struct sk_buff *skb) {
    struct iphdr *iph = ip_hdr(skb);
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = tcp_hdr(skb);
        // TO DO UDP and ICMP
        if (isLocalIP(iph->saddr) && !isLocalIP(iph->daddr)) {
            // Out NAT
            // first, search the nat list
            struct nat *n = matchNat(iph->saddr, tcph->source);
            if (n != NULL) {    // if matched, then do the transfer
                iph->saddr = n->ip_pub;
                tcph->source = n->port_pub;
            } else {    // if not, random new a port and add it to the list
                struct nat tmp = {iph->saddr, pub_ip, tcph->source, tcph->source+1024, NULL};
                addNat(&tmp);
                iph->saddr = pub_ip;
                tcph->source += 1024;
            }
        } else if (!isLocalIP(iph->saddr) && matchIPaddr(iph->daddr, pub_ip, 32)) {
            // In NAT 
            struct nat *n = matchNat(iph->daddr, tcph->dest);
            if (n != NULL) {    // if matched, then do the transfer
                iph->daddr = n->ip_loc;
                tcph->dest = n->port_loc;
            }
        }
        UpdateChecksum(skb);
    }
    return;
}
//
unsigned int net_forward(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph = ip_hdr(skb);
    printk("nat : saddr = %hhu.%hhu.%hhu.%hhu, daddr = %hhu.%hhu.%hhu.%hhu\n",
        ((unsigned char *)&(iph->saddr))[0], ((unsigned char *)&(iph->saddr))[1],
        ((unsigned char *)&(iph->saddr))[2], ((unsigned char *)&(iph->saddr))[3], 
        ((unsigned char *)&(iph->daddr))[0], ((unsigned char *)&(iph->daddr))[1], 
        ((unsigned char *)&(iph->daddr))[2], ((unsigned char *)&(iph->daddr))[3]);
    unsigned int ret = NF_DROP;
    if (isLocalIP(iph->saddr) && !isLocalIP(iph->daddr)) {
        // from LAN to WAN
        // a demo for nat_filter
        struct Quintuple pkt_info;
        struct status *stat;
        
        getQuintuple(skb, &pkt_info);

        stat = matchStatus(&pkt_info);
        if (stat != NULL) { // stat matched
            NATtransfer(skb);
            ret = NF_ACCEPT;
        } else {    // stat not matched
            // the SYN packet?
            if (getTCPflags(skb, SYN)) {
                // matched rules list
                unsigned int action = regularMatcher(&pkt_info);
                // if permitted, add to the stat list
                if (action || defaultStrategy == DEFAULT_PERMIT) {
                    addStatus(&pkt_info);
                    NATtransfer(skb);
                    ret = NF_ACCEPT;
                }
            } else if (defaultStrategy == DEFAULT_PERMIT) {
                NATtransfer(skb);
                ret = NF_ACCEPT;
            }
        }
    } else {
        ret = NF_ACCEPT;
    }
    return ret;
}
//
unsigned int net_pre_route(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    // a demo for net_filter
    unsigned int ret = NF_DROP;
    struct Quintuple pkt_info;
    struct Quintuple tmp;
    struct status *stat;
    // info print
    struct iphdr *iph = ip_hdr(skb);
    printk("pre routing in : saddr = %hhu.%hhu.%hhu.%hhu, daddr = %hhu.%hhu.%hhu.%hhu\n",
        ((unsigned char *)&(iph->saddr))[0], ((unsigned char *)&(iph->saddr))[1],
        ((unsigned char *)&(iph->saddr))[2], ((unsigned char *)&(iph->saddr))[3], 
        ((unsigned char *)&(iph->daddr))[0], ((unsigned char *)&(iph->daddr))[1], 
        ((unsigned char *)&(iph->daddr))[2], ((unsigned char *)&(iph->daddr))[3]);
    if (!isLocalIP(iph->saddr) && matchIPaddr(iph->daddr, pub_ip, 32)) {
        NATtransfer(skb);
        getQuintuple(skb, &pkt_info);
        tmp.saddr = pkt_info.daddr;
        tmp.source = pkt_info.dest;
        tmp.daddr = pkt_info.saddr;
        tmp.dest = pkt_info.source;
        stat = matchStatus(&tmp);
        if (stat != NULL) { // stat matched
            struct timeval tv;
            do_gettimeofday(&tv);
            stat->last_t = tv.tv_sec;
            ret = NF_ACCEPT;
        } else {    // stat not matched
            // the SYN packet?
            if (getTCPflags(skb, SYN)) {
                unsigned int action = regularMatcher(&pkt_info);
                // if permitted, add to the stat list
                if (action || defaultStrategy == DEFAULT_PERMIT) {
                    addStatus(&tmp);
                    ret = NF_ACCEPT;
                } 
            } else if (defaultStrategy == DEFAULT_PERMIT) {
                ret = NF_ACCEPT;
            }
        }
    } else {
        ret = NF_ACCEPT;
    }
    return ret;
}
//
unsigned int net_filter_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph = ip_hdr(skb);
    printk("filter out : saddr = %hhu.%hhu.%hhu.%hhu, daddr = %hhu.%hhu.%hhu.%hhu\n",
        ((unsigned char *)&(iph->saddr))[0], ((unsigned char *)&(iph->saddr))[1],
        ((unsigned char *)&(iph->saddr))[2], ((unsigned char *)&(iph->saddr))[3], 
        ((unsigned char *)&(iph->daddr))[0], ((unsigned char *)&(iph->daddr))[1], 
        ((unsigned char *)&(iph->daddr))[2], ((unsigned char *)&(iph->daddr))[3]);
    // a demo for net_filter
    struct Quintuple pkt_info;
    struct status *stat;
    unsigned int ret = NF_DROP;
    getQuintuple(skb, &pkt_info);

    stat = matchStatus(&pkt_info);
    if (stat != NULL) { // stat matched
        ret = NF_ACCEPT;
    } else {    // stat not matched
        // the SYN packet?
        if (getTCPflags(skb, SYN)) {
            // matched rules list
            unsigned int action = regularMatcher(&pkt_info);
            // if permitted, add to the stat list
            if (action || defaultStrategy == DEFAULT_PERMIT) {
                addStatus(&pkt_info);
                ret = NF_ACCEPT;
            }
        } else if (defaultStrategy == DEFAULT_PERMIT) {
            ret = NF_ACCEPT;
        }
    }
    return ret;
}
//
static int __init initFirewall(void){
    // To initialize the device
    /* initialize cdev struct */
    cdev_init(&cdev, &fops);
     /* register char device */
    alloc_chrdev_region(&devno, 0, 1, "theFirewall");
    cdev_add(&cdev, devno, 1); // add a char device
    dev_opened = 0;
    rules_num = 0;
    audit_num = 0;
    local_ip = 171430666;
    pub_ip = 67635208;
    ttl = 20;
    defaultStrategy = DEFAULT_REJECT;
    
    printk("my firewall module loaded.\n");

    nfho_out.hook = net_filter_out;
    nfho_out.pf = PF_INET;
    nfho_out.hooknum = NF_INET_LOCAL_OUT;
    nfho_out.priority = NF_IP_PRI_FIRST;

    nfho_in.hook = net_pre_route;
    nfho_in.pf = PF_INET;
    nfho_in.hooknum = NF_INET_PRE_ROUTING;
    nfho_in.priority = NF_IP_PRI_FIRST;

    nfho_nat.hook = net_forward;
    nfho_nat.pf = PF_INET;
    nfho_nat.hooknum = NF_INET_FORWARD;
    nfho_nat.priority = NF_IP_PRI_FIRST;

    initStatHashTable();
    initNAThashTable();

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
        nf_register_net_hook(&init_net, &nfho_in);
        nf_register_net_hook(&init_net, &nfho_out);
        nf_register_net_hook(&init_net, &nfho_nat);
    #else
        nf_register_hook(&nfho_out);
        nf_register_hook(&nfho_in);
        nf_register_hook(&nfho_nat);
    #endif
    return 0;
}
//
static void __exit exitFirewall(void){
    // To uninstall the module
    cdev_del(&cdev);   // delete the char device
    unregister_chrdev_region(devno, 1); // release the char device number

    printk("my firewall module exit ...\n");

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
        nf_unregister_net_hook(&init_net, &nfho_out);
        nf_unregister_net_hook(&init_net, &nfho_in);
        nf_unregister_net_hook(&init_net, &nfho_nat);
    #else
        nf_unregister_hook(&nfho_out);
        nf_unregister_hook(&nfho_in);
        nf_unregister_hook(&nfho_nat);
    #endif
    
}
module_init(initFirewall);
module_exit(exitFirewall);
MODULE_LICENSE("GPL");


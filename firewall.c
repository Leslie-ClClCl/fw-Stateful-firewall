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

#define multiple_32 2654435769
#define multiple_8 158
#define bufSize 0x10000
typedef unsigned long long ULL;



int dev_opened;
unsigned char dev_mem[DEV_SZ];
unsigned rules_num;
unsigned audit_num;
struct cdev cdev;
dev_t devno;
static struct nf_hook_ops nfho_out, nfho_in;

struct rule {
    unsigned int    saddr;    // source IP address
    unsigned int    daddr;    // dest IP address
    unsigned char    smask;    // source IP mask
    unsigned char    dmask;    // dest IP mask
    unsigned int source;    // source port
    unsigned int dest;    // dest port
    unsigned char protocol;    // protocol

    unsigned char audit;        // whether to log information
    unsigned char action;    // permit or reject
} rules[500];

struct Quintuple {
    unsigned int  saddr;    // source IP address
    unsigned int  daddr;    // dest IP address
    unsigned int  source;    // source port
    unsigned int  dest;    // dest port
    unsigned char    protocol;    // protocol
};

struct status {
    unsigned int saddr;
    unsigned int daddr;
    unsigned int source;
    unsigned int dest;
    unsigned char stat;
    struct status *next;
} statList[bufSize];



// Declarations of my own operation functions
int     open(struct inode *, struct file *);
int     release(struct inode *, struct file *);
ssize_t read(struct file *, char __user *, size_t, loff_t *);
ssize_t write(struct file *, const char __user *, size_t, loff_t *);
loff_t     llseek(struct file *, loff_t, int);
long     ioctl(struct file *, unsigned int, unsigned long);

// Declarations of all the functions
void initStatHashTable(void);
ULL getHash(struct Quintuple *q);
struct status *matchStatus(struct Quintuple *q);
void addStatus(struct Quintuple *q);
int getQuintuple(struct sk_buff *skb, struct Quintuple *info);
int matchIPaddr(unsigned int addr1, unsigned int addr2, unsigned char shortmask);
unsigned int regularMatcher(struct Quintuple *pkt_info);
unsigned int net_filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static int __init initFirewall(void);
static void __exit exitFirewall(void);
unsigned char getTCPflags(struct sk_buff *skb, unsigned char FLAG);


// Associating function entry points
static const struct file_operations fops = {
  .owner = THIS_MODULE,
  .open = open,
  .release = release,
  // .read = read,
  .write = write,
  // .llseek = llseek,
  // .unlocked_ioctl = ioctl,
};


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                      Functions for device operations              //////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
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
ssize_t write(struct file *filp, const char __user *buffer, size_t size, loff_t *offset) {
    // To write to the device
    int count = 0;
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
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                             functional funcs              //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int getQuintuple(struct sk_buff *skb, struct Quintuple *info) {
    // get info from IP packet
    if (skb == NULL  || info == NULL)
        return -1;

    struct iphdr *iph;
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
    if (tcph == NULL)
        return 0;
    unsigned char flag = *((unsigned char *)tcph + 13);
    // TO DO verify the correctness
    return flag & FLAG;
}
//
int matchIPaddr(unsigned int addr1, unsigned int addr2, unsigned char shortmask) {
    // match the mask
    unsigned mask = 0xffffffff;
    mask = mask << (32-shortmask);
    return (addr1 & mask) == (addr2 & mask);
}
//
// to determine the action
unsigned int regularMatcher(struct Quintuple *pkt_info) {
    int i;
    if (pkt_info == NULL) {
        printk("null ptr");
        return NF_DROP;
    }
    // printk("from %d.%d.%d.%d to %d.%d.%d.%d, sport %d dport %d\n",
    //        ((unsigned char *)&(pkt_info->saddr))[0], ((unsigned char *)&(pkt_info->saddr))[1],
    //        ((unsigned char *)&(pkt_info->saddr))[2], ((unsigned char *)&(pkt_info->saddr))[3],
    //        ((unsigned char *)&(pkt_info->daddr))[0], ((unsigned char *)&(pkt_info->daddr))[1],
    //        ((unsigned char *)&(pkt_info->daddr))[2], ((unsigned char *)&(pkt_info->daddr))[3],
    //        pkt_info->source, pkt_info->dest);
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
        printk("%s\n", rules[i].action ? "Permit" : "Reject");
        return rules[i].action;
    }
    printk("Reject\n");
    return NF_DROP;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                          Net Filter Complement                       //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void initStatHashTable(void) {
    int i = 0;
    for (i = 0; i < bufSize; i++) {
        statList[i].next = NULL;
    }
    return;
}
//
ULL getHash(struct Quintuple *q) {
    // get a quintuple's hash value
    ULL res = 0;
    res += (q->saddr * multiple_32);
    res += (q->daddr * multiple_32);
    res += (q->source * multiple_8);
    res += (q->dest * multiple_8);
    return res >> 28;
}
//
struct status *matchStatus(struct Quintuple *q) {
    // match the quintuple on the status list
    // if matched, return the pointer, else return null
    ULL hashValue = getHash(q);
    struct status *head = statList[hashValue].next;
    while (head != NULL) {
        if (q->saddr == head->saddr && q->daddr == head->daddr && q->source == head->source && q->dest == head->stat) {
            printk("status list matched!\n");
            return head;
        }
        head = head->next;
    }
    printk("status list not matched!\n");
    return NULL;
}
//
void addStatus(struct Quintuple *q) {
    // add a new status infomation onto the hash table
    ULL hashValue = getHash(q);
    struct status *ptr = (struct status*)kmalloc(sizeof(struct status), GFP_KERNEL);
    
    ptr->saddr = q->saddr;
    ptr->daddr = q->daddr;
    ptr->source = q->source;
    ptr->dest = q->dest;
    ptr->next = NULL;
    
    struct status *head = statList[hashValue].next;
    ptr->next = head->next;
    head->next = ptr;
    printk("status has added to the list\n");
    return;
}
//
unsigned int net_filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    // a demo for net_filter
    struct Quintuple pkt_info;
    getQuintuple(skb, &pkt_info);

    printk("--from %d.%d.%d.%d to %d.%d.%d.%d, sport %d dport %d\n",
           ((unsigned char *)&(pkt_info.saddr))[0], ((unsigned char *)&(pkt_info.saddr))[1],
           ((unsigned char *)&(pkt_info.saddr))[2], ((unsigned char *)&(pkt_info.saddr))[3],
           ((unsigned char *)&(pkt_info.daddr))[0], ((unsigned char *)&(pkt_info.daddr))[1],
           ((unsigned char *)&(pkt_info.daddr))[2], ((unsigned char *)&(pkt_info.daddr))[3],
           pkt_info.source, pkt_info.dest);

    struct status *stat = matchStatus(&pkt_info);
    if (stat != NULL) { // stat matched
        printk("STAT MATCHED ACCEPT!\n");
        return NF_ACCEPT;
    } else {    // stat not matched
        // the SYN packet?
        if (getTCPflags(skb, SYN)) {
            printk("SYN Packet ACCEPT!\n");
            // matched rules list
            unsigned int action = regularMatcher(&pkt_info);
            // if permitted, add to the stat list
            if (action) {
                printk("Rules Permits ACCEPT!\n");
                addStatus(&pkt_info);
                return NF_ACCEPT;
            } else {
                printk("Rules Denied DROP!\n");
                return NF_DROP;
            }
        } else {
            printk("Not SYN DROP!\n");
            return NF_DROP;
        }
    }
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
    printk("my firewall module loaded.\n");

    nfho_out.hook = net_filter;
    nfho_out.pf = PF_INET;
    nfho_out.hooknum = NF_INET_LOCAL_OUT;
    nfho_out.priority = NF_IP_PRI_FIRST;

    nfho_in.hook = net_filter;
    nfho_in.pf = PF_INET;
    nfho_in.hooknum = NF_INET_LOCAL_IN;
    nfho_in.priority = NF_IP_PRI_FIRST;

    initStatHashTable();
    
    nf_register_hook(&nfho_out);
    nf_register_hook(&nfho_in);
    return 0;
}
//
static void __exit exitFirewall(void){
    // To uninstall the module
    cdev_del(&cdev);   // delete the char device
    unregister_chrdev_region(devno, 1); // release the char device number

    printk("my firewall module exit ...\n");
    nf_unregister_hook(&nfho_out);
    nf_unregister_hook(&nfho_in);
}

module_init(initFirewall);
module_exit(exitFirewall);
MODULE_LICENSE("GPL");


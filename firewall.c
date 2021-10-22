
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
struct sk_buff *sock_buff;
struct iphdr *ip_header;
static int blackOrwhite=100;
static int port[50];
static char ip_list[50][50];
static char   message[256] = {0};
static int index=0;
static int white_flag=0;
static int    majorNumber;
#define  DEVICE_NAME "firewall"
#define  CLASS_NAME  "Fire"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Reza abbasi");
MODULE_DESCRIPTION("firewall module");
MODULE_VERSION("1");


static struct class*  firewallClass  = NULL;
static struct device* firewallDevice = NULL;

static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

static struct file_operations fops =
{
   .write = dev_write,
};

unsigned int icmp_hook(unsigned int hooknum, struct sk_buff *skb,
                       const struct net_device *in, const struct net_device *out,
                       int(*okfn)(struct sk_buff *));


static struct nf_hook_ops icmp_drop __read_mostly = {
        .pf = NFPROTO_IPV4,
        .priority = NF_IP_PRI_FIRST,
        .hooknum =NF_INET_LOCAL_IN,
        .hook = (nf_hookfn *) icmp_hook
};

//#################################################################################################
static int __init firewall_init(void)
{
///////////////////////////////////////////////////////////////////////////////////////////////////
 int ret = nf_register_net_hook(&init_net,&icmp_drop);
 if(ret)
     printk(KERN_INFO "FAILED");
///////////////////////////////////////////////////////////////////////////////////////////////////
     majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
     if (majorNumber<0){
        printk(KERN_ALERT "EBBChar failed to register a major number\n");
        return majorNumber;
     }
//////////////////////////////////////////////////////////////////////////////////////////////////
firewallClass = class_create(THIS_MODULE, CLASS_NAME);
if (IS_ERR(firewallClass)){
   unregister_chrdev(majorNumber, DEVICE_NAME);
   printk(KERN_ALERT "Failed to register device class\n");
   return PTR_ERR(firewallClass);
}
/////////////////////////////////////////////////////////////////////////////////////////////////
firewallDevice = device_create(firewallClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
if (IS_ERR(firewallDevice)){
   class_destroy(firewallClass);
   unregister_chrdev(majorNumber, DEVICE_NAME);
   printk(KERN_ALERT "Failed to create the device\n");
   return PTR_ERR(firewallDevice);
 }

return 0;
}
//#############################################################################################
static void __exit  firewall_exit(void)
{
        nf_unregister_net_hook(&init_net,&icmp_drop);
        device_destroy(firewallClass, MKDEV(majorNumber, 0));
        class_unregister(firewallClass);
        class_destroy(firewallClass);
        unregister_chrdev(majorNumber, DEVICE_NAME);

}
//##############################################################################################

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
    copy_from_user(message, buffer,250);
     int dec=0;
     int i=0;
     char ip[50];
    if (message[0]=='b')
    {
      blackOrwhite=0;
    }
    else if(message[0]=='w')
    {
      blackOrwhite=1;
    }
    else{

      while(message[i]!=':')
        {
          ip[i]=message[i];
          i++;
    }
    ip[i]='\0';
     i++;

     while(message[i]>47)
     {
      	dec = dec * 10 + ( message[i] - '0' );
       i++;
      }
      strcpy(ip_list[index],ip);
      port[index]=dec;

        index++;
    }


    return 1;
}

//#################################################################################

unsigned int icmp_hook(unsigned int hooknum, struct sk_buff *skb,

        const struct net_device *in, const struct net_device *out,

        int(*okfn)(struct sk_buff *))

{
        sock_buff = skb;
        ip_header = (struct iphdr *)skb_network_header(sock_buff);
        if(!sock_buff) { return NF_DROP;}

      char str[16];
snprintf(str, 16, "%pI4", &ip_header->saddr);


  unsigned int dst_port=0;


            white_flag=0;
            int i=0;
            for(i=0;i<index;i++)
            {
                if(strcmp(str,ip_list[i])==0)
                {
                  white_flag=1;
                  break;
                }
            }

          if(white_flag==0)
           {
              if(blackOrwhite==0){
                printk(KERN_INFO "packet receive\n");
                  return NF_ACCEPT;
                }
              else
              {
                  printk(KERN_INFO "packet drop\n");
                  return NF_DROP;
                }
            }
             if(white_flag)
            {
              if(ip_header->protocol == IPPROTO_UDP)
              {
        struct udphdr *udph;
        udph = udp_hdr(skb);
        dst_port = (unsigned int)ntohs(udph->source);

            }

          else  if(ip_header->protocol == IPPROTO_TCP)
      {
        struct tcphdr *tcph;
        tcph = tcp_hdr(skb);
        dst_port = (unsigned int)ntohs(tcph->source);

      }

          if(dst_port==port[i])
          {
            if(blackOrwhite==0)
            {
            printk(KERN_INFO "packet drop\n");
            return  NF_DROP;
          }
            else
            {
            printk(KERN_INFO "packet drop\n");
            return  NF_ACCEPT;
          }
          }


            }

          return 0;
}

//################################################################################################################



module_init(firewall_init);
module_exit(firewall_exit);

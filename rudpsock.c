#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/errno.h>
#include <linux/types.h> 
#include <linux/netdevice.h> 
#include <linux/ip.h> 
#include <linux/in.h> 
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include <asm/byteorder.h>

#define rudpsock_pr_fmt(x) "rudp sock: " x
#define RECV_BUF_SIZE 512
#define MAX_RETRANS_COUNT 10

static u32 ip = 0x7f000001u; /* 127.0.0.1 */
static s32 dstport = 8000;
static s32 srcport = 8080;

module_param(ip, uint, 0644);
MODULE_PARM_DESC(ip, "Destination IP Address");
module_param(dstport, int, 0644);
MODULE_PARM_DESC(dstport, "Destination port number");
module_param(srcport, int, 0644);
MODULE_PARM_DESC(srcport, "Source port number");

struct rudp_header_t
{
	bool fin,syn,rst,ack;
	__be32 acked;
	__be32 seq;
	__be32 window;
};

enum rudpstate_t
{
	RUDP_CLOSED,
	RUDP_LISTEN,
	RUDP_SYN_SENT,
	RUDP_SYN_RCVD,
	RUDP_ESTAB,
	RUDP_FIN_WAIT_1,
	RUDP_FIN_WAIT_2,
	RUDP_CLOSING,
	RUDP_TIME_WAIT,
	RUDP_CLOSE_WAIT,
	RUDP_LAST_ACK
};

struct rudppkt_t
{
	unsigned char *pkt;
	int len;
	ktime_t start;
	int timeout_count;
	struct list_head node;
	int last;
};

struct rudpcb_t
{
	unsigned char is_in_rudp_mode;
	enum rudpstate_t state;
	int lastack;
	int acked;
	int seq;
	bool mustRetrans;
	spinlock_t lock;
};

struct kthread_t
{
	struct task_struct *thread;
	struct task_struct *send_thread;
	struct socket *sock;
	struct sockaddr_in addr;
	struct socket *sock_send;
	struct sockaddr_in addr_send;
	struct rudpcb_t cb;
};

struct recvlog_t
{
	unsigned char *buf;
	struct list_head node;
};

static struct kthread_t *kthread = NULL;
static struct proc_dir_entry *rudp_server = NULL;

static LIST_HEAD(recvlogs);
static LIST_HEAD(sendlist);
static LIST_HEAD(retranslist);
static DEFINE_SPINLOCK(lock);
static DEFINE_SPINLOCK(sendlock);

static struct rudppkt_t* new_pkt(int syn, int ack, int rst, int fin, 
		unsigned char* buf, int len, struct rudpcb_t *cb)
{
	struct rudppkt_t *pkt = kmalloc(sizeof(struct rudppkt_t),GFP_KERNEL);
	unsigned char* pktbuf = kzalloc(sizeof(struct rudp_header_t)+
			(len+1)*sizeof(unsigned char), GFP_KERNEL);
	struct rudp_header_t *header = (struct rudp_header_t*)pktbuf;

	memset(header, 0, sizeof(struct rudp_header_t));
	header->fin = fin;
	header->syn = syn;
	header->ack = ack;
	header->rst = rst;
	header->seq = htonl(cb->seq);

	if (len != 0) {
		strncpy(pktbuf+sizeof(struct rudp_header_t), buf, len);
		cb->seq += len;
	} else if (syn|ack) {
		++cb->seq;
	}

	pkt->pkt = pktbuf;
	pkt->len = len*sizeof(unsigned char) + sizeof(struct rudp_header_t);
	pkt->last = cb->seq;
	pkt->timeout_count = 0;
	INIT_LIST_HEAD(&pkt->node);
	return pkt;
}

static inline int is_pure_ack(int len, struct rudp_header_t *header)
{
	return len == sizeof(struct rudp_header_t) &&
		header->ack && !header->syn && !header->rst && !header->fin;
}

static inline int is_start_with(
		unsigned char pattern[], 
		unsigned char str[],
		size_t len_pattern,
		size_t len)
{
	int i;
	if (len_pattern > len) {
		return 0;
	}
	for (i = 0; i < len_pattern; ++i) {
	//	printk(KERN_DEBUG rudpsock_pr_fmt("%d %d\n"),pattern[i],str[i]);
		if (pattern[i] != str[i]) {
			return 0;
		}
	}
	return 1;
}

static int rudp_send(unsigned char *buf, int len)
{
	struct msghdr msg;
	struct kvec vec;
	if (kthread == NULL || kthread->sock_send == NULL) {
		printk(KERN_ALERT rudpsock_pr_fmt("rudp_send invalid!\n"));
		return -EINVAL;
	}

	vec.iov_base = buf;
	vec.iov_len = len;

	msg.msg_flags = 0;
	msg.msg_name = &kthread->addr_send;
	msg.msg_namelen = sizeof(struct sockaddr_in);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_iocb = NULL;

	return kernel_sendmsg(kthread->sock_send, &msg, &vec, 1, len);
}

static int rudp_receive(unsigned char *buf, int len)
{
	struct msghdr msg;
	struct kvec vec;

	if (kthread == NULL || kthread->sock == NULL) {
		return -EINVAL;
	}

	vec.iov_base = buf;
	vec.iov_len = len;

	msg.msg_flags = 0;
	msg.msg_name = &kthread->addr;
	msg.msg_namelen = sizeof(struct sockaddr_in);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_iocb = NULL;

	return kernel_recvmsg(kthread->sock, &msg, &vec, 1, len, msg.msg_flags);
}

static unsigned char *rudp_send_rst(struct rudpcb_t *cb)
{
	static unsigned char send_rst_msg[] = rudpsock_pr_fmt("Reset packet sent!\n");
	unsigned char *ret = kzalloc(sizeof(send_rst_msg),GFP_KERNEL);
	cb->is_in_rudp_mode = 0;
	cb->state = RUDP_CLOSED;

	printk(KERN_DEBUG rudpsock_pr_fmt("%s\n"),send_rst_msg);
	spin_lock_bh(&sendlock);
	list_add_tail(&new_pkt(0,0,1,0,NULL,0,cb)->node, &sendlist);
	spin_unlock_bh(&sendlock);

	strcpy(ret,send_rst_msg);
	return ret;
}

static unsigned char *rudp_send_syn(struct rudpcb_t *cb)
{
	static unsigned char send_syn_msg[] = rudpsock_pr_fmt("SYN packet sent!\n");
	unsigned char *ret = kzalloc(sizeof(send_syn_msg),GFP_KERNEL);
	cb->state = RUDP_SYN_SENT;
	
	printk(KERN_DEBUG rudpsock_pr_fmt("%s\n"),send_syn_msg);
	spin_lock_bh(&sendlock);
	list_add_tail(&new_pkt(1,0,0,0,NULL,0,cb)->node, &sendlist);
	spin_unlock_bh(&sendlock);

	strcpy(ret,send_syn_msg);
	return ret;
}

static unsigned char *rudp_send_synack(struct rudpcb_t *cb)
{
	static unsigned char send_synack_msg[] = rudpsock_pr_fmt("SYN+ACK packet sent!\n");
	unsigned char *ret = kzalloc(sizeof(send_synack_msg),GFP_KERNEL);
	cb->state = RUDP_SYN_RCVD;

	printk(KERN_DEBUG rudpsock_pr_fmt("%s\n"),send_synack_msg);
	spin_lock_bh(&sendlock);
	list_add_tail(&new_pkt(1,1,0,0,NULL,0,cb)->node, &sendlist);
	spin_unlock_bh(&sendlock);

	strcpy(ret,send_synack_msg);
	return ret;
}

static unsigned char *rudp_send_ack(struct rudpcb_t *cb)
{
	static unsigned char send_ack_msg[] = rudpsock_pr_fmt("ACK packet sent!\n");
	unsigned char *ret = kzalloc(sizeof(send_ack_msg),GFP_KERNEL);
	
	printk(KERN_DEBUG rudpsock_pr_fmt("%s\n"),send_ack_msg);
	spin_lock_bh(&sendlock);
	list_add_tail(&new_pkt(0,1,0,0,NULL,0,cb)->node, &sendlist);
	spin_unlock_bh(&sendlock);

	strcpy(ret,send_ack_msg);
	return ret;
}

static unsigned char *rudp_established(struct rudpcb_t *cb)
{
	static unsigned char estab_msg[] = rudpsock_pr_fmt("Established!\n");
	unsigned char *ret = kzalloc(sizeof(estab_msg),GFP_KERNEL);
	cb->state = RUDP_ESTAB;

	strcpy(ret,estab_msg);
	return ret;
}

static unsigned char* rudp_do_recv(unsigned char *buf,
		ssize_t len,
		struct rudpcb_t *cb)
{
	static unsigned char rst_msg[] = "Connection reset. Fall back to udp mode.\n";
	struct rudp_header_t *header = NULL;
	unsigned char* content = NULL;
	unsigned char *ret = NULL;
	int _pkt_ack = 0;

	if (len < sizeof(struct rudp_header_t)) {
		goto rst;
	}

	header = (struct rudp_header_t*)buf;
	if (len > sizeof(struct rudp_header_t)) {
		content = (unsigned char*) (buf+sizeof(struct rudp_header_t));
	}

	if (header->rst) {
		ret = kzalloc(sizeof(rst_msg),GFP_KERNEL);
		cb->state = RUDP_CLOSED;
		cb->is_in_rudp_mode = 0;
		
		strcpy(ret,rst_msg);
		return ret;
	}

	/*printk(KERN_DEBUG rudpsock_pr_fmt("seq=%d, acked=%d\n"),
				ntohl(header->seq),cb->acked);
	*/
	if (header->ack) {	
		if (cb->lastack < ntohl(header->acked)) {
			cb->lastack = ntohl(header->acked);
		} else {
			cb->mustRetrans = 1;
		}
	}

	if (ntohl(header->seq) != cb->acked) {
		if (is_pure_ack(len,header)) return NULL;
		return rudp_send_ack(cb);
	}


	switch (cb->state)
	{
		case RUDP_LISTEN:
			if (header->syn &&
			    !header->ack &&
			    !header->fin) {
				printk(KERN_DEBUG rudpsock_pr_fmt("LISTEN"));
				_pkt_ack = ntohl(header->seq) + 1;
				cb->acked = cb->acked > _pkt_ack ? 
					cb->acked : _pkt_ack;
				return rudp_send_synack(cb);
			}
			break;
		case RUDP_SYN_RCVD:
			if (header->ack &&
			    !header->syn &&
			    !header->fin) {
				_pkt_ack = ntohl(header->seq) + 1;
				cb->acked = cb->acked > _pkt_ack ? 
					cb->acked : _pkt_ack;
				return rudp_established(cb);
			}
			break;
		case RUDP_SYN_SENT:
			if (header->syn && !header->fin) {
				if (header->ack) {
					cb->state = RUDP_ESTAB;
				} else {
					cb->state = RUDP_SYN_RCVD;
				}
				_pkt_ack = ntohl(header->seq) + 1;
				cb->acked = cb->acked > _pkt_ack ? 
					cb->acked : _pkt_ack;
				return rudp_send_ack(cb);
			}
			break;
		case RUDP_ESTAB:
			ret = kzalloc(len-sizeof(struct rudp_header_t),GFP_KERNEL);
			strncpy(ret, content, len-sizeof(struct rudp_header_t));
			if (!is_pure_ack(len, header)) {
				spin_lock_bh(&sendlock);
				if (list_empty(&sendlist)) {
					list_add_tail(&new_pkt(0,1,0,0,NULL,0,cb)->node,
						&sendlist);
				}
				spin_unlock_bh(&sendlock);
			}
			_pkt_ack = len - sizeof(struct rudp_header_t) == 0 ?
				ntohl(header->seq) + 1 :
				ntohl(header->seq) + len - sizeof(struct rudp_header_t);
			cb->acked = cb->acked > _pkt_ack ? cb->acked : _pkt_ack;
			return ret;
		default:
			break;
	}

rst:
	return rudp_send_rst(cb);
}

static unsigned char* rudp_process_recv(unsigned char *buf,
		ssize_t len,
		struct rudpcb_t* cb)
{
	unsigned char *ret = NULL;
	
	if (cb->is_in_rudp_mode) {
		spin_lock_bh(&cb->lock);
		ret = rudp_do_recv(buf,len,cb);
		spin_unlock_bh(&cb->lock);
	}
	else {
		/* Normal UDP Mode */
		ret = kzalloc((len+1), GFP_KERNEL);
		strcpy(ret, buf);
	}
	return ret;
}

static int rudp_socket_init(void)
{
	int err = 0;

	memset(&kthread->cb,0,sizeof(kthread->cb));

	/* Create socket for receiving message. */
	err = sock_create(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &kthread->sock);
	if (err < 0) {
		printk(KERN_ALERT
			rudpsock_pr_fmt("Cannot create socket for UDP, err=%d\n"),
			err);
		return -EINVAL;
	}

	/* Create socket for sending message */
	err = sock_create(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &kthread->sock_send);
	if (err < 0) {
		printk(KERN_ALERT
			rudpsock_pr_fmt("Cannot create sock for UDP, err=%d\n"),
			err);
		return -EINVAL;
	}

	memset(&kthread->addr, 0, sizeof(struct sockaddr));
	kthread->addr.sin_family = AF_INET;
	kthread->addr.sin_addr.s_addr = htonl(INADDR_ANY);
	kthread->addr.sin_port = htons(srcport);

	memset(&kthread->addr_send, 0, sizeof(struct sockaddr));
	kthread->addr_send.sin_family = AF_INET;
	kthread->addr_send.sin_addr.s_addr = htonl(ip);
	kthread->addr_send.sin_port = htons(dstport);

	err = kernel_bind(kthread->sock, 
			(struct sockaddr*)&kthread->addr, 
			sizeof(struct sockaddr));
	if (err < 0) {
		printk(KERN_ALERT
			rudpsock_pr_fmt("Bind faild!, err=%d\n"),
			err);
		return -EINVAL;
	}

	err = kernel_connect(kthread->sock_send, 
			(struct sockaddr*)&kthread->addr_send, 
			sizeof(struct sockaddr), 0);
	if (err < 0) {
		printk(KERN_ALERT
			rudpsock_pr_fmt("Connect failed! err=%d\n"),
			err);
		return -EINVAL;
	}

	return 0;
}

static int rudp_server_start(void *data)
{
	int size;
	unsigned char buf[RECV_BUF_SIZE]={0};
	struct recvlog_t *recvlog = NULL;

	allow_signal(SIGKILL);
	while (!kthread_should_stop()) {
		size = rudp_receive(buf, RECV_BUF_SIZE);
		if (size < 0) {
			printk(KERN_ALERT
				rudpsock_pr_fmt("kernel_recvmsg error, err=%d\n"),
				size);
			break;
		}
		
		recvlog = kmalloc(sizeof(struct recvlog_t), GFP_KERNEL);
		recvlog->buf = rudp_process_recv(buf, size, &kthread->cb);
		if (recvlog->buf == NULL) {
			kfree(recvlog);
			recvlog = NULL;
			continue;
		}
		spin_lock_bh(&lock);
		list_add_tail(&recvlog->node, &recvlogs);
		spin_unlock_bh(&lock);
	}
	return 0;
}

static void display_pkt(struct rudppkt_t *pkt)
{
	struct rudp_header_t *header = (struct rudp_header_t*)pkt->pkt;
	//int i;
	printk(KERN_DEBUG rudpsock_pr_fmt("len:%d\n"),pkt->len);
	printk(KERN_DEBUG rudpsock_pr_fmt("header: syn %d ack %d rst %d fin %d seq %d acked %d\n"),
			header->syn,header->ack,header->rst,header->fin,
			ntohl(header->seq),ntohl(header->acked));
	/*for (i = 0; i < pkt->len; ++i) {
		printk(KERN_DEBUG "%d/", pkt->pkt[i]);
	}*/
}

static int rudp_send_thread(void *data)
{
	struct rudppkt_t *pkt;
	struct list_head *entry, *i, *j;
	struct rudp_header_t *header = NULL;
	ktime_t curr;
	int lastack = 0;
	allow_signal(SIGKILL);

	while (!kthread_should_stop()) {
		entry = NULL;
		spin_lock_bh(&sendlock);
		curr = ktime_get();
		if (!list_empty(&sendlist)) {
			entry = sendlist.next;
			pkt = list_entry(entry,struct rudppkt_t,node);
			pkt->start = curr;
			header = (struct rudp_header_t*)pkt->pkt;
			if (header->ack) {
				header->acked = htonl(kthread->cb.acked);
			} else if (!header->syn) {
				header->ack = 1;
				header->acked = htonl(kthread->cb.acked);
			}
			//display_pkt(pkt);
			if (rudp_send(pkt->pkt, pkt->len) < 0) {
				goto err;
			}
			//printk(KERN_DEBUG rudpsock_pr_fmt("reach here!\n"));
			list_del(entry);
		}
		spin_unlock_bh(&sendlock);

		lastack = kthread->cb.lastack;
		//printk(KERN_DEBUG rudpsock_pr_fmt("lastack:%d\n"),lastack);
		list_for_each_safe(i, j, &retranslist) {
			pkt = list_entry(i,struct rudppkt_t,node);
			if (pkt->timeout_count > MAX_RETRANS_COUNT) {
				kthread->cb.is_in_rudp_mode = 0;
				kthread->cb.state = RUDP_CLOSED;
				kthread->cb.acked = 0;
				kthread->cb.seq = 0;
				break;
			}
			if (pkt->last <= lastack) {
				list_del(i);
				kfree(pkt->pkt);
				kfree(pkt);
				continue;
			}
			if (ktime_after(curr,ktime_add_ns(pkt->start, 2000000000))) {
				header = (struct rudp_header_t*)pkt->pkt;
				if (kthread->cb.state == RUDP_ESTAB &&
					is_pure_ack(pkt->len, header)) {
					printk(KERN_DEBUG 
						rudpsock_pr_fmt("seq=%d,lastack=%d,re=%d\n"),
						ntohl(header->seq),lastack,
						kthread->cb.mustRetrans);
					if (!(ntohl(header->seq) == lastack &&
						kthread->cb.mustRetrans)) {
						continue;
					}
					kthread->cb.mustRetrans = 0;
				}
				list_del(i);
				pkt->timeout_count++;
				spin_lock_bh(&sendlock);
				list_add(i,&sendlist);
				spin_unlock_bh(&sendlock);
			}
		}

		spin_lock_bh(&sendlock);
		if (entry != NULL) {
			pkt = list_entry(entry,struct rudppkt_t,node);
/*			if (is_pure_ack(pkt->len, (struct rudp_header_t*)pkt->pkt)) {
				kfree(pkt->pkt);
				kfree(pkt);
			} else {
*/
				list_add_tail(entry, &retranslist);
//			}
		}
		spin_unlock_bh(&sendlock);

		if (list_empty(&sendlist)) {
			schedule_timeout_interruptible(HZ>>3);
		}
	}

	return 0;
err:
	printk(KERN_ALERT rudpsock_pr_fmt("error occured!\n"));
	return -1;
}

static int rudp_server_show(struct seq_file *m, void *v)
{
	struct recvlog_t *recvlog = NULL;
	spin_lock_bh(&lock);
	while (!list_empty(&recvlogs)) {
		recvlog = list_entry(recvlogs.next, struct recvlog_t, node);
		seq_printf(m,"%s",recvlog->buf);
		list_del(recvlogs.next);
		kfree(recvlog->buf);
		kfree(recvlog);
	}
	spin_unlock_bh(&lock);
	return 0;
}

static ssize_t rudp_server_write(struct file *file, const char __user *buffer,
		size_t count, loff_t *f_pos)
{
	static char connect[] = "@connect";
	static size_t connect_len = sizeof(connect)/sizeof(unsigned char)-1;//skip \0
	static char listen[] = "@listen";
	static size_t listen_len = sizeof(listen)/sizeof(unsigned char)-1;//skip \0
	struct recvlog_t *recvlog = NULL;
	char *tmp = kzalloc((count+1),GFP_KERNEL);
	if (!tmp) {
		return -ENOMEM;
	}
	if (copy_from_user(tmp, buffer, count))
	{
		kfree(tmp);
		return -EFAULT;
	}

	if (!kthread->cb.is_in_rudp_mode) {
		/* Check the keyword @connect and @listen*/
		//printk(KERN_DEBUG rudpsock_pr_fmt("%d\n"),is_start_with(connect,tmp,connect_len,count));
		if (is_start_with(connect,tmp,connect_len,count)) {
			printk(KERN_DEBUG rudpsock_pr_fmt("connect matched\n"));
			kthread->cb.is_in_rudp_mode = 1;
			kthread->cb.state = RUDP_SYN_SENT;
			recvlog = kmalloc(sizeof(struct recvlog_t), GFP_KERNEL);
			recvlog->buf = rudp_send_syn(&kthread->cb);
			spin_lock_bh(&lock);
			list_add_tail(&recvlog->node, &recvlogs);
			spin_unlock_bh(&lock);
			return count;
		} else if (is_start_with(listen,tmp,listen_len,count)) {
			printk(KERN_DEBUG rudpsock_pr_fmt("listen matched\n"));
			kthread->cb.is_in_rudp_mode = 1;
			kthread->cb.state = RUDP_LISTEN;
			return count;
		}
		if (rudp_send(tmp,count) < 0) {
			goto error;
		}
	} else {
		if (kthread->cb.state == RUDP_ESTAB) {
			spin_lock_bh(&sendlock);
			list_add_tail(&new_pkt(0,0,0,0,tmp,count,&kthread->cb)->node,
					&sendlist);
			spin_unlock_bh(&sendlock);
			return count;
		}
		goto error;
	}
	kfree(tmp);

	return count;
error:
	kfree(tmp);
	return -EINVAL;
}

static int rudp_server_open(struct inode *inode, struct file *file)
{
	return single_open(file, rudp_server_show, NULL);
}

static struct file_operations server_fops = {
	.owner	= THIS_MODULE,
	.open	= rudp_server_open,
	.release= single_release,
	.read	= seq_read,
	.llseek = seq_lseek,
	.write	= rudp_server_write
};

int __init rudpsock_init(void)
{
	kthread = kmalloc(sizeof(struct kthread_t), GFP_KERNEL);
	memset(kthread, 0, sizeof(struct kthread_t));

	spin_lock_init(&kthread->cb.lock);
	if (rudp_socket_init() < 0) {
		return -EINVAL;
	}

	kthread->thread = kthread_run((void*)rudp_server_start, NULL, "rudpserver");
	if (IS_ERR(kthread->thread)) {
		printk(KERN_INFO rudpsock_pr_fmt("Unable to launch a kernel thread"));
		goto thread_err;
	}
	kthread->send_thread = kthread_run((void*)rudp_send_thread, NULL, "rudpsend");
	if (IS_ERR(kthread->send_thread)) {
		printk(KERN_INFO rudpsock_pr_fmt("Unable to launch a kernel thread"));
		goto send_thread_err;
	}

	rudp_server = proc_create("rudp_server", 0666, 
			init_net.proc_net, &server_fops);
	if (!rudp_server) {
		printk(KERN_ALERT rudpsock_pr_fmt("Unable to create proc file"));
		goto send_thread_err;
	}

	return 0;
send_thread_err:
	kfree(kthread->thread);
thread_err:
	kfree(kthread);
	kthread = NULL;
	return -ENOMEM;
}

void __exit rudpsock_exit(void)
{
	if (kthread->thread != NULL) {
		kthread_stop(kthread->thread);
	}

	if (kthread->thread != NULL) {
		kthread_stop(kthread->send_thread);
	}

	if (kthread->sock != NULL) {
		sock_release(kthread->sock);
		kthread->sock = NULL;
	}

	if (kthread->sock_send != NULL) {
		sock_release(kthread->sock_send);
	}

	kfree(kthread);
	kthread = NULL;

	remove_proc_entry("rudp_server", init_net.proc_net);
}

module_init(rudpsock_init);
module_exit(rudpsock_exit);

MODULE_AUTHOR("Luming Wang");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Reliable UDP Server in Kernel");
MODULE_VERSION("0.1");


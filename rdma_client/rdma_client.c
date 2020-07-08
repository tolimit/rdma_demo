#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/inet.h>
#include <linux/slab.h>

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include <rdma/rw.h>



struct rdma_info {
	u64 buf;
	u32 key;
	u32 size;
};

enum rdma_struct_flags_bit {
	ADDR_RESOLVED = 0,
	ROUTE_RESOLVED,
};

struct rdma_struct {
	unsigned long flags;
	unsigned int error;
	struct sockaddr_storage sin;

	struct rdma_cm_id *cm_id;
	struct rdma_cm_event *event;
	struct rdma_listener *listener;

	struct ib_cq *cq;
	struct ib_pd *pd;
	struct ib_qp *qp;

	struct rdma_info recv_buf;

	struct ib_mr *reg_mr;

	wait_queue_head_t wait;
};

struct rdma_struct rdma_d;

static int do_alloc_qp(struct rdma_cm_id *cm_id, struct ib_pd *pd, struct ib_cq *cq);
static struct ib_cq *do_alloc_cq(struct rdma_cm_id *cm_id);

static void rdma_cq_event_handler(struct ib_cq *cq, void *ctx)
{
	int ret;
	struct ib_wc wc;
	struct rdma_struct *rdma_d = ctx;

	while ((ret = ib_poll_cq(rdma_d->cq, 1, &wc)) == 1) {
		printk("opcode=0x%x, state=%d.\n", wc.opcode, wc.status);
	}
}

static int rdma_cm_handler(struct rdma_cm_id *cm_id, struct rdma_cm_event *event)
{
	int err = 0;
	struct rdma_struct *rdma_d = cm_id->context;
	struct rdma_conn_param conn_param = {0};
	struct ib_pd *pd;
	struct ib_cq *cq;

	if (cm_id != rdma_d->cm_id) {
		printk(KERN_ERR "cm_id is diff.\n");
	}
	switch (event->event) {
		case RDMA_CM_EVENT_ADDR_RESOLVED:
			printk(KERN_ERR "event is ADDR_RESOLVED.\n");
			set_bit(ADDR_RESOLVED, &rdma_d->flags);
			err = rdma_resolve_route(rdma_d->cm_id, 2000);
			if (err) {
				printk(KERN_ERR "resolve route failed.\n");
				rdma_d->error = 1;
				wake_up_interruptible(&rdma_d->wait);
			}
			break;
		case RDMA_CM_EVENT_CONNECT_REQUEST:
			printk(KERN_ERR "event is connect_request.\n");
			break;
		case RDMA_CM_EVENT_ESTABLISHED:
			printk(KERN_ERR "event is ESTABLISHED.\n");
			break;
		case RDMA_CM_EVENT_DISCONNECTED:
			printk(KERN_ERR "event is DISCONNECTED.\n");
			break;
		case RDMA_CM_EVENT_ROUTE_RESOLVED:
			printk(KERN_ERR "event is ROUTE_RESOLVED.\n");
			set_bit(ROUTE_RESOLVED, &rdma_d->flags);
			// alloc pd
			if (cm_id->device == NULL) {
				printk(KERN_ERR "device is NULL\n");
				err = -ENOMEM;
				break;
			}
			pd = ib_alloc_pd(cm_id->device, 0);
			if (IS_ERR(pd)) {
				printk(KERN_ERR "alloc pd failed.\n");
				err = PTR_ERR(pd);
				rdma_d->error = 1;
				break;
			}
			// create cq
			cq = do_alloc_cq(cm_id);
			if (IS_ERR(cq)) {
				printk(KERN_ERR "alloc cq failed.\n");
				rdma_d->error = 1;
				err = PTR_ERR(cq);
				ib_dealloc_pd(pd);
				break;
			}
			// create qp
			err = do_alloc_qp(cm_id, pd, cq);
			if (err < 0) {
				printk(KERN_ERR "alloc qp failed.\n");
				rdma_d->error = 1;
				ib_destroy_cq(cq);
				ib_dealloc_pd(pd);
				break;
			}
			conn_param.responder_resources = 1;
			conn_param.initiator_depth = 1;
			conn_param.retry_count = 10;
			printk(KERN_ERR "do connect.\n");
//			ret = rdma_connect(rdma_d.cm_id, &conn_param);
			err = rdma_connect(cm_id, &conn_param);
			if (err < 0) {
				printk(KERN_ERR "connect failed.\n");
			}

			break;
		default:
			printk(KERN_ERR "event is unrecognized(event=0x%x).\n", event->event);
			break;
	}

	return err;
}

static int do_rdma_resolve_addr(struct rdma_struct *rdma_d, struct sockaddr_in *addr)
{
	int ret = rdma_resolve_addr(rdma_d->cm_id, NULL, (struct sockaddr *)addr, 2000);
	if (ret < 0) {
		printk(KERN_ERR "resolve failed.\n");
		return ret;
	}

	return ret;
}

static void init_rdma_struct(struct rdma_struct *rdma_d)
{
	init_waitqueue_head(&rdma_d->wait);
}

static int do_alloc_qp(struct rdma_cm_id *cm_id, struct ib_pd *pd, struct ib_cq *cq)
{
	struct ib_qp_init_attr qp_attr = {0};

	qp_attr.send_cq = cq;
	qp_attr.recv_cq = cq;
	qp_attr.qp_type = IB_QPT_RC;

	qp_attr.cap.max_send_wr = 128;
	qp_attr.cap.max_recv_wr = 128;
	qp_attr.cap.max_send_sge = 1;
	qp_attr.cap.max_recv_sge = 1;

	return rdma_create_qp(cm_id, pd, &qp_attr);
}

static struct ib_cq *do_alloc_cq(struct rdma_cm_id *cm_id)
{
	struct ib_cq_init_attr cq_attr = {0};

	cq_attr.cqe = 128 * 2;
	cq_attr.comp_vector = 0;
	return ib_create_cq(cm_id->device, rdma_cq_event_handler, NULL, cm_id, &cq_attr);
//	return ib_req_notify_cq(rdma_d->cq, IB_CQ_NEXT_COMP);
}

static int __init rdma_init(void)
{
	int ret = 0;
	struct sockaddr_in *addr;
	char *s_ip = "192.168.122.109";
	char _addr[16] = {0};
	int port = 1;

	addr = (struct sockaddr_in *)&rdma_d.sin;
	addr->sin_family = AF_INET;
	addr->sin_port = port;
	in4_pton(s_ip, -1, _addr, -1, NULL);
	memcpy((void *)&addr->sin_addr.s_addr, _addr, 4);

	init_rdma_struct(&rdma_d);
	rdma_d.cm_id = rdma_create_id(&init_net, rdma_cm_handler, &rdma_d, RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(rdma_d.cm_id)) {
		printk(KERN_ERR "create cm_id failed.\n");
		return 0;
	}

	// waiting RDMA_CM_EVENT_ROUTE_RESOLVED;
	ret = do_rdma_resolve_addr(&rdma_d, addr);
	if (ret < 0)
		goto destroy_cm_id;

	return 0;

destroy_cm_id:
	if (rdma_d.qp && !IS_ERR(rdma_d.qp)) {
		ib_destroy_qp(rdma_d.qp);
		rdma_d.qp = NULL;
	}
	if (rdma_d.cq && !IS_ERR(rdma_d.cq)) {
		ib_destroy_cq(rdma_d.cq);
		rdma_d.cq = NULL;
	}
	if (rdma_d.pd && !IS_ERR(rdma_d.pd)) {
		ib_dealloc_pd(rdma_d.pd);
		rdma_d.pd = NULL;
	}
	if (rdma_d.cm_id) {
		rdma_destroy_id(rdma_d.cm_id);
		rdma_d.cm_id = NULL;
	}
	return ret;
}

static void __exit rdma_exit(void) {
	if (rdma_d.qp && !IS_ERR(rdma_d.qp)) {
		ib_destroy_qp(rdma_d.qp);
	}
	if (rdma_d.cq && !IS_ERR(rdma_d.cq)) {
		ib_destroy_cq(rdma_d.cq);
	}
	if (rdma_d.pd && !IS_ERR(rdma_d.pd)) {
		ib_dealloc_pd(rdma_d.pd);
	}
	if (rdma_d.cm_id) {
		rdma_destroy_id(rdma_d.cm_id);
	}
}

MODULE_LICENSE("GPLv2");
module_init(rdma_init);
module_exit(rdma_exit);

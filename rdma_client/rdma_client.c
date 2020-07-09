#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/device.h>

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include <rdma/rw.h>

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

	struct ib_pd *pd;
	struct ib_cq *cq;
	struct ib_mr *mr;

#define BUF_SIZE	256		// 256 * 16 = 4096
	struct ib_sge recv_sgl;
	struct ib_recv_wr rq_wr;
	char *recv_buf;
	dma_addr_t recv_dma_addr;	// dma addr of recv_buf

	struct ib_sge send_sgl;
	struct ib_send_wr sq_wr;
	char *send_buf;
	dma_addr_t send_dma_addr;	// dma addr of send_buf

	struct ib_sge rdma_sgl;
	struct ib_rdma_wr rdma_sq_wr;
	char *rdma_buf;
	dma_addr_t rdma_dma_addr;	// dma addr of rdma_buf

	struct ib_reg_wr reg_mr_wr;

	wait_queue_head_t wait;
};

struct rdma_struct rdma_d;

static int do_alloc_qp(struct rdma_cm_id *cm_id, struct ib_pd *pd, struct ib_cq *cq);
static struct ib_cq *do_alloc_cq(struct rdma_cm_id *cm_id);

static void init_requests(struct rdma_struct *rdma_d)
{
	// recv request
	rdma_d->recv_sgl.addr = rdma_d->recv_dma_addr;
	rdma_d->recv_sgl.length = PAGE_SIZE;
	rdma_d->recv_sgl.lkey = rdma_d->pd->local_dma_lkey;

	rdma_d->rq_wr.sg_list = &rdma_d->recv_sgl;
	rdma_d->rq_wr.num_sge = 1;

	// send request
	rdma_d->send_sgl.addr = rdma_d->send_dma_addr;
	rdma_d->send_sgl.length = PAGE_SIZE;
	rdma_d->send_sgl.lkey = rdma_d->pd->local_dma_lkey;

	rdma_d->sq_wr.opcode = IB_WR_SEND;
	rdma_d->sq_wr.send_flags = IB_SEND_SIGNALED;
	rdma_d->sq_wr.sg_list = &rdma_d->send_sgl;
	rdma_d->sq_wr.num_sge = 1;

	// rdma request
	rdma_d->rdma_sgl.addr = rdma_d->rdma_dma_addr;
	rdma_d->rdma_sq_wr.wr.send_flags = IB_SEND_SIGNALED;
	rdma_d->rdma_sq_wr.wr.sg_list = &rdma_d->rdma_sgl;
	rdma_d->rdma_sq_wr.wr.num_sge = 1;

	// reg mr request
	rdma_d->reg_mr_wr.wr.opcode = IB_WR_REG_MR;
	rdma_d->reg_mr_wr.mr = rdma_d->mr;
}

static int prepare_buffer(struct rdma_struct *rdma_d)
{
	rdma_d->recv_buf = (char *)__get_free_page(GFP_KERNEL | GFP_DMA);
	if (IS_ERR(rdma_d->recv_buf)) {
		printk(KERN_ERR "alloc recv_buf failed.\n");
		return -ENOMEM;
	}
	rdma_d->send_buf = (char *)__get_free_page(GFP_KERNEL | GFP_DMA);
	if (IS_ERR(rdma_d->send_buf)) {
		printk(KERN_ERR "alloc send_buf failed.\n");
		goto free_recv_buf;
	}
	rdma_d->recv_dma_addr = ib_dma_map_single(rdma_d->pd->device, rdma_d->recv_buf, PAGE_SIZE, DMA_BIDIRECTIONAL);
	rdma_d->send_dma_addr = ib_dma_map_single(rdma_d->pd->device, rdma_d->send_buf, PAGE_SIZE, DMA_BIDIRECTIONAL);
	rdma_d->rdma_buf = ib_dma_alloc_coherent(rdma_d->pd->device, PAGE_SIZE, &rdma_d->rdma_dma_addr, GFP_KERNEL);
	if (!rdma_d->rdma_buf || !rdma_d->send_dma_addr || !rdma_d->recv_dma_addr) {
		printk(KERN_ERR "map dma addr failed\n");
		goto free_dma_addr;
	}

	rdma_d->mr = ib_alloc_mr(rdma_d->pd, IB_MR_TYPE_MEM_REG, PAGE_SIZE);
	if (IS_ERR(rdma_d->mr)) {
		printk(KERN_ERR "alloc mr failed.\n");
		goto free_dma_addr;
	}

	init_requests(rdma_d);

	return 0;
free_dma_addr:
	if (rdma_d->recv_dma_addr)
		ib_dma_unmap_single(rdma_d->pd->device, (unsigned long)rdma_d->recv_buf, PAGE_SIZE, DMA_BIDIRECTIONAL);
	if (rdma_d->send_dma_addr)
		ib_dma_unmap_single(rdma_d->pd->device, (unsigned long)rdma_d->send_buf, PAGE_SIZE, DMA_BIDIRECTIONAL);
	if (rdma_d->rdma_buf)
		ib_dma_free_coherent(rdma_d->pd->device, PAGE_SIZE, rdma_d->rdma_buf, rdma_d->rdma_dma_addr);
	free_page((unsigned long)rdma_d->send_buf);
free_recv_buf:
	free_page((unsigned long)rdma_d->recv_buf);
	return -ENOMEM;
}

static void destroy_buffer(struct rdma_struct *rdma_d)
{
	if (rdma_d->mr)
		ib_dereg_mr(rdma_d->mr);
	if (rdma_d->recv_dma_addr)
		ib_dma_unmap_single(rdma_d->pd->device, (unsigned long)rdma_d->recv_buf, PAGE_SIZE, DMA_BIDIRECTIONAL);
	if (rdma_d->send_dma_addr)
		ib_dma_unmap_single(rdma_d->pd->device, (unsigned long)rdma_d->send_buf, PAGE_SIZE, DMA_BIDIRECTIONAL);
	if (rdma_d->rdma_buf)
		ib_dma_free_coherent(rdma_d->pd->device, PAGE_SIZE, rdma_d->rdma_buf, rdma_d->rdma_dma_addr);
	if (rdma_d->send_buf)
		free_page((unsigned long)rdma_d->send_buf);
	if (rdma_d->recv_buf)
		free_page((unsigned long)rdma_d->recv_buf);
}

static void rdma_cq_event_handler(struct ib_cq *cq, void *ctx)
{
	printk(KERN_ERR "111\n");

/*	while ((ret = ib_poll_cq(rdma_d->cq, 1, &wc)) == 1) {
		printk("opcode=0x%x, state=%d.\n", wc.opcode, wc.status);
	}
	*/
}

static int send_mr(struct rdma_struct *rdma_d)
{
	const struct ib_send_wr *bad_wr;
	int ret = 0;
	u8 key = 0;
	struct scatterlist sg = {0};

	ib_update_fast_reg_key(rdma_d->mr, ++key);
	rdma_d->reg_mr_wr.key = rdma_d->mr->rkey;
	rdma_d->reg_mr_wr.access = IB_ACCESS_REMOTE_READ | IB_ACCESS_LOCAL_WRITE;
//	sg_dma_address(&sg) = rdma_d->send_buf;
	sg_dma_address(&sg) = rdma_d->send_dma_addr;
	sg_dma_len(&sg) = PAGE_SIZE;

	ret = ib_map_mr_sg(rdma_d->mr, &sg, 1, NULL, PAGE_SIZE);
	if (ret < 0 || ret > PAGE_SIZE) {
		printk(KERN_ERR "map_mr_sg failed\n");
		return -1;
	}

	ret = ib_post_send(rdma_d->cm_id->qp, &rdma_d->reg_mr_wr.wr, &bad_wr);
	if (ret) {
		printk(KERN_ERR "post reg_mr_wr failed\n");
		return -2;
	}

	return 0;
}

static int send_data(struct rdma_struct *rdma_d)
{
	const struct ib_send_wr *bad_wr;
	int ret;
	struct ib_wc wc = {0};

	ret = send_mr(rdma_d);

	memcpy(rdma_d->send_buf, "abccba", 7);
	ret = ib_post_send(rdma_d->cm_id->qp, &rdma_d->sq_wr, &bad_wr);
	if (ret) {
		printk(KERN_ERR "post sq_wr failed\n");
		return -2;
	}

	while ((ret = ib_poll_cq(rdma_d->cq, 1, &wc)) == 0);

	if (ret < 0) {
		printk(KERN_ERR "poll cq failed\n");
		return -3;
	}
	printk("opcode=0x%x, state=%d.\n", wc.opcode, wc.status);

	return 0;
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
			printk(KERN_ERR "start send data.\n");
			err = send_data(rdma_d);
			if (err) {
				printk(KERN_ERR "send data failed.\n");
			} else {
				printk(KERN_ERR "send data done.\n");
			}
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

			rdma_d->pd = pd;
			rdma_d->cq = cq;
			prepare_buffer(rdma_d);
			conn_param.responder_resources = 1;
			conn_param.initiator_depth = 1;
			conn_param.retry_count = 10;
			printk(KERN_ERR "do connect.\n");
			err = rdma_connect(rdma_d->cm_id, &conn_param);
//			err = rdma_connect(cm_id, &conn_param);
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
//	return ib_alloc_cq(cm_id->device, cm_id, 128 * 2, 0, IB_POLL_WORKQUEUE)
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
	if (rdma_d.cm_id) {
		if (rdma_d.cm_id->qp && !IS_ERR(rdma_d.cm_id->qp))
			ib_destroy_qp(rdma_d.cm_id->qp);
		rdma_destroy_id(rdma_d.cm_id);
		rdma_d.cm_id = NULL;
	}
	if (rdma_d.cq && !IS_ERR(rdma_d.cq)) {
		ib_destroy_cq(rdma_d.cq);
		rdma_d.cq = NULL;
	}
	if (rdma_d.pd && !IS_ERR(rdma_d.pd)) {
		ib_dealloc_pd(rdma_d.pd);
		rdma_d.pd = NULL;
	}
	return ret;
}

static void __exit rdma_exit(void) {
	if (rdma_d.cm_id) {
		if (rdma_d.cm_id->qp && !IS_ERR(rdma_d.cm_id->qp))
			ib_destroy_qp(rdma_d.cm_id->qp);
		rdma_destroy_id(rdma_d.cm_id);
	}
	destroy_buffer(&rdma_d);
	if (rdma_d.cq && !IS_ERR(rdma_d.cq)) {
		ib_destroy_cq(rdma_d.cq);
	}
	if (rdma_d.pd && !IS_ERR(rdma_d.pd)) {
		ib_dealloc_pd(rdma_d.pd);
	}
}

MODULE_LICENSE("GPLv2");
module_init(rdma_init);
module_exit(rdma_exit);

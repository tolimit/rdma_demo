#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/gfp.h>

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include <rdma/rw.h>


enum rdma_struct_flags_bit {
	ADDR_RESOLVED = 0,
	ROUTE_RESOLVED,
};

struct rdma_connection {
	unsigned long state;
	struct rdma_cm_id *cm_id;

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

	struct list_head list;
	struct work_struct disconnect_work;
};

struct rdma_struct {
	unsigned long flags;
	struct sockaddr_storage sin;

	struct rdma_cm_id *cm_id;
	struct rdma_cm_event *event;
	struct rdma_listener *listener;

	struct ib_mr *reg_mr;

	wait_queue_head_t wait;

	struct mutex connection_lock;
	struct list_head connection_list;
};

struct rdma_struct rdma_d;

static int do_alloc_qp(struct rdma_cm_id *cm_id, struct ib_pd *pd, struct ib_cq *cq);
static struct ib_cq *do_alloc_cq(struct rdma_cm_id *cm_id);

static void init_requests(struct rdma_connection *rdma_c)
{
	// recv request
	rdma_c->recv_sgl.addr = rdma_c->recv_dma_addr;
	rdma_c->recv_sgl.length = PAGE_SIZE;
	rdma_c->recv_sgl.lkey = rdma_c->pd->local_dma_lkey;

	rdma_c->rq_wr.sg_list = &rdma_c->recv_sgl;
	rdma_c->rq_wr.num_sge = 1;

	// send request
	rdma_c->send_sgl.addr = rdma_c->send_dma_addr;
	rdma_c->send_sgl.length = PAGE_SIZE;
	rdma_c->send_sgl.lkey = rdma_c->pd->local_dma_lkey;

	rdma_c->sq_wr.opcode = IB_WR_SEND;
	rdma_c->sq_wr.send_flags = IB_SEND_SIGNALED;
	rdma_c->sq_wr.sg_list = &rdma_c->send_sgl;
	rdma_c->sq_wr.num_sge = 1;

	// rdma request
	rdma_c->rdma_sgl.addr = rdma_c->rdma_dma_addr;
	rdma_c->rdma_sq_wr.wr.send_flags = IB_SEND_SIGNALED;
	rdma_c->rdma_sq_wr.wr.sg_list = &rdma_c->rdma_sgl;
	rdma_c->rdma_sq_wr.wr.num_sge = 1;

	// reg mr request
	rdma_c->reg_mr_wr.wr.opcode = IB_WR_REG_MR;
	rdma_c->reg_mr_wr.mr = rdma_c->mr;
}

static int prepare_buffer(struct rdma_connection *rdma_c)
{
	rdma_c->recv_buf = (char *)__get_free_page(GFP_KERNEL | GFP_DMA);
	if (IS_ERR(rdma_c->recv_buf)) {
		printk(KERN_ERR "alloc recv_buf failed.\n");
		return -ENOMEM;
	}
	rdma_c->send_buf = (char *)__get_free_page(GFP_KERNEL | GFP_DMA);
	if (IS_ERR(rdma_c->send_buf)) {
		printk(KERN_ERR "alloc send_buf failed.\n");
		goto free_recv_buf;
	}
	rdma_c->recv_dma_addr = ib_dma_map_single(rdma_c->pd->device, rdma_c->recv_buf, PAGE_SIZE, DMA_BIDIRECTIONAL);
	rdma_c->send_dma_addr = ib_dma_map_single(rdma_c->pd->device, rdma_c->send_buf, PAGE_SIZE, DMA_BIDIRECTIONAL);
	rdma_c->rdma_buf = ib_dma_alloc_coherent(rdma_c->pd->device, PAGE_SIZE, &rdma_c->rdma_dma_addr, GFP_KERNEL);
	if (!rdma_c->rdma_buf || !rdma_c->send_dma_addr || !rdma_c->recv_dma_addr) {
		printk(KERN_ERR "map dma addr failed\n");
		goto free_dma_addr;
	}

	rdma_c->mr = ib_alloc_mr(rdma_c->pd, IB_MR_TYPE_MEM_REG, PAGE_SIZE);
	if (IS_ERR(rdma_c->mr)) {
		printk(KERN_ERR "alloc mr failed.\n");
		goto free_dma_addr;
	}
	
	init_requests(rdma_c);

	return 0;
free_dma_addr:
	if (rdma_c->recv_dma_addr)
		ib_dma_unmap_single(rdma_c->pd->device, (unsigned long)rdma_c->recv_buf, PAGE_SIZE, DMA_BIDIRECTIONAL);
	if (rdma_c->send_dma_addr)
		ib_dma_unmap_single(rdma_c->pd->device, (unsigned long)rdma_c->send_buf, PAGE_SIZE, DMA_BIDIRECTIONAL);
	if (rdma_c->rdma_buf)
		ib_dma_free_coherent(rdma_c->pd->device, PAGE_SIZE, rdma_c->rdma_buf, rdma_c->rdma_dma_addr);
	free_page((unsigned long)rdma_c->send_buf);
free_recv_buf:
	free_page((unsigned long)rdma_c->recv_buf);
	return -ENOMEM;
}

static int add_to_connection_list(struct rdma_cm_id *cm_id, struct ib_pd *pd, struct ib_cq *cq)
{
	struct rdma_connection *_new = kzalloc(sizeof(struct rdma_connection), GFP_KERNEL);
	if (_new == NULL)
		return -ENOMEM;

	_new->cm_id = cm_id;
	_new->pd = pd;
	_new->cq = cq;
	cm_id->context = _new;
	INIT_LIST_HEAD(&_new->list);
	if (prepare_buffer(_new)) {
		kfree(_new);
		return -ENOMEM;
	}
	printk(KERN_ERR "new connection 0x%p\n", _new);
	mutex_lock(&rdma_d.connection_lock);
	list_add_tail(&rdma_d.connection_list, &_new->list);
	mutex_unlock(&rdma_d.connection_lock);

	return 0;
}

static int do_accept(struct rdma_cm_id *cm_id, struct rdma_cm_event *event)
{
	struct rdma_conn_param conn_param;
	int err = 0;
	struct ib_pd *pd = NULL;
	struct ib_cq *cq = NULL;
	struct rdma_connection *rdma_c = NULL;
	const struct ib_recv_wr *bad_wr;

	// alloc pd
	if (cm_id->device == NULL) {
		printk(KERN_ERR "device is NULL\n");
		return -ENOMEM;
	}
	pd = ib_alloc_pd(cm_id->device, 0);
	if (IS_ERR(pd)) {
		printk(KERN_ERR "alloc pd failed.\n");
		err = PTR_ERR(pd);
		goto failed;;
	}
	printk(KERN_ERR "alloc pd\n");
	// create cq
	cq = do_alloc_cq(cm_id);
	if (IS_ERR(cq)) {
		printk(KERN_ERR " alloc cq failed.\n");
		err = PTR_ERR(cq);
		goto failed;
	}
//	ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
	printk(KERN_ERR "alloc cq\n");
	// create qp
	err = do_alloc_qp(cm_id, pd, cq);
	if (err) {
		printk(KERN_ERR "alloc qp failed. error=%d\n", err);
		goto failed;
	}
	printk(KERN_ERR "alloc qp\n");
	memset(&conn_param, 0x0, sizeof(struct rdma_conn_param));
	conn_param.responder_resources = 1;
	conn_param.initiator_depth = 1;

	if ((err = add_to_connection_list(cm_id, pd, cq)))
		goto failed;

	rdma_c = cm_id->context;
	err = ib_post_recv(cm_id->qp, &rdma_c->rq_wr, &bad_wr);
	if (err) {
		printk(KERN_ERR "post recv failed.\n");
		goto out;
	}
	err = rdma_accept(cm_id, &conn_param);
	if (err) {
		printk(KERN_ERR "accept failed, error=%d.\n", err);
		// we destroy it when doing rmmod
		goto out;
	}

	return 0;
failed:
	if (cm_id->qp && !IS_ERR(cm_id->qp)) {
		ib_destroy_qp(cm_id->qp);
	}
	if (cq && !IS_ERR(cq)) {
		ib_destroy_cq(cq);
	}
	if (pd && !IS_ERR(pd)) {
		ib_dealloc_pd(pd);
	}
	
out:
	return err;
}

static void rdma_cq_event_handler(struct ib_cq *cq, void *ctx)
{
	int ret;
	struct ib_wc wc;
	struct rdma_cm_id *cm_id = cq->cq_context;
	struct rdma_connection *rdma_c =cm_id->context;
	const struct ib_recv_wr *bad_wr;

	printk(KERN_ERR "enter cq_event_handler.\n");
	if ((ret = ib_poll_cq(cq, 1, &wc)) == 1) {
		printk(KERN_ERR "opcode=0x%x, state=%d.\n", wc.opcode, wc.status);
		printk(KERN_ERR "recv_buf[0]=%c.\n", rdma_c->recv_buf[0]);
		printk(KERN_ERR "rdma_buf[0]=%c.\n", rdma_c->rdma_buf[0]);
		if (ib_post_recv(cm_id->qp, &rdma_c->rq_wr, &bad_wr))
			printk("1 post_recv failed.\n");
	}
//	ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
	printk(KERN_ERR "exit cq_event_handler.\n");
}

static void destroy_buffer(struct rdma_connection *rdma_c)
{
	if (rdma_c->mr)
		ib_dereg_mr(rdma_c->mr);
	if (rdma_c->recv_dma_addr)
		ib_dma_unmap_single(rdma_c->pd->device, (unsigned long)rdma_c->recv_buf, PAGE_SIZE, DMA_BIDIRECTIONAL);
	if (rdma_c->send_dma_addr)
		ib_dma_unmap_single(rdma_c->pd->device, (unsigned long)rdma_c->send_buf, PAGE_SIZE, DMA_BIDIRECTIONAL);
	if (rdma_c->rdma_buf)
		ib_dma_free_coherent(rdma_c->pd->device, PAGE_SIZE, rdma_c->rdma_buf, rdma_c->rdma_dma_addr);
	if (rdma_c->send_buf)
		free_page((unsigned long)rdma_c->send_buf);
	if (rdma_c->recv_buf)
		free_page((unsigned long)rdma_c->recv_buf);
}

static void do_disconnect(struct work_struct *work)
{
	struct rdma_connection *rdma_c = container_of(work, struct rdma_connection, disconnect_work);

	mutex_lock(&rdma_d.connection_lock);
	printk(KERN_ERR "do disconnect 0x%p.\n", rdma_c);
	list_del_init(&rdma_c->list);
	BUG_ON(rdma_c->cm_id == NULL);
	rdma_disconnect(rdma_c->cm_id);
	ib_drain_qp(rdma_c->cm_id->qp);
	destroy_buffer(rdma_c);
	ib_destroy_qp(rdma_c->cm_id->qp);
	rdma_destroy_id(rdma_c->cm_id);
	ib_free_cq(rdma_c->cq);
	ib_dealloc_pd(rdma_c->pd);

	kfree(rdma_c);
	printk(KERN_ERR "do disconnect finished.\n");
	mutex_unlock(&rdma_d.connection_lock);
}

static int rdma_cm_handler(struct rdma_cm_id *cm_id, struct rdma_cm_event *event) {
	int err = 0;
	struct rdma_connection *pos, *next;

	switch (event->event) {
		case RDMA_CM_EVENT_CONNECT_REQUEST:
			printk(KERN_ERR "event is connect_request.\n");
			err = do_accept(cm_id, event);
			break;
		case RDMA_CM_EVENT_ESTABLISHED:
			printk(KERN_ERR "event is ESTABLISHED.\n");
			break;
		case RDMA_CM_EVENT_DISCONNECTED:
			printk(KERN_ERR "event is DISCONNECTED.\n");
			// we cannot destroy cm_id in current context, it will cause deadlock
			mutex_lock(&rdma_d.connection_lock);
			list_for_each_entry_safe(pos, next, &rdma_d.connection_list, list) {
				if (pos->cm_id == cm_id) {
					INIT_WORK(&pos->disconnect_work, do_disconnect);
					schedule_work(&pos->disconnect_work);
					break;
				}
			}
			mutex_unlock(&rdma_d.connection_lock);
			break;
		default:
			printk(KERN_ERR "event is unrecognized.\n");
			break;
	}

	return err;
}

static void init_rdma_struct(struct rdma_struct *rdma_d)
{
	init_waitqueue_head(&rdma_d->wait);
	INIT_LIST_HEAD(&rdma_d->connection_list);
	mutex_init(&rdma_d->connection_lock);
}

static int do_alloc_qp(struct rdma_cm_id *cm_id, struct ib_pd *pd, struct ib_cq *cq)
{
	struct ib_qp_init_attr qp_attr = {0};

	qp_attr.qp_context = cm_id;
//	qp_attr.event_handler = rdma_qp_event_handler;
	qp_attr.send_cq = cq;
	qp_attr.recv_cq = cq;
	qp_attr.qp_type = IB_QPT_RC;

	qp_attr.cap.max_send_wr = 128;
	qp_attr.cap.max_recv_wr = 128;
	qp_attr.cap.max_send_sge = 1;
	qp_attr.cap.max_recv_sge = 1;
	qp_attr.sq_sig_type = IB_SIGNAL_REQ_WR;

	return rdma_create_qp(cm_id, pd, &qp_attr);
}

static struct ib_cq *do_alloc_cq(struct rdma_cm_id *cm_id)
{
	struct ib_cq_init_attr cq_attr = {0};

	cq_attr.cqe = 128 * 2;
	cq_attr.comp_vector = 0;
	return ib_create_cq(cm_id->device, rdma_cq_event_handler, NULL, cm_id, &cq_attr);
}

static int __init rdma_init(void) {
	int ret;
	struct sockaddr_in *addr;
	char *ip = "192.168.122.109";
	char _addr[16] = {0};
	int port = 1;

	addr = (struct sockaddr_in *)&rdma_d.sin;
	addr->sin_family = AF_INET;
	addr->sin_port = port;
	in4_pton(ip, -1, _addr, -1, NULL);
	memcpy((void *)&addr->sin_addr.s_addr, _addr, 4);
//	in4_pton(SERVER_IP, -1, rdma_d.addr, -1, NULL); 
//	memcpy((void *)&addr->sin_addr.s_addr, rdma_d.addr, 4);

	init_rdma_struct(&rdma_d);
	rdma_d.cm_id = rdma_create_id(&init_net, rdma_cm_handler, &rdma_d, RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(rdma_d.cm_id)) {
		printk(KERN_ERR "create cm_id failed.\n");
		return 0;
	}

	ret = rdma_bind_addr(rdma_d.cm_id, (struct sockaddr *)addr);
	if (ret < 0) {
		printk(KERN_ERR "bind failed.\n");
		goto destroy_cm_id;
	}

	ret = rdma_listen(rdma_d.cm_id, 10);
	if (ret < 0) {
		printk(KERN_ERR "listen failed.\n");
		goto destroy_cm_id;
	}

	return 0;

destroy_cm_id:
	if (rdma_d.cm_id) {
		rdma_destroy_id(rdma_d.cm_id);
		rdma_d.cm_id = NULL;
	}
	return ret;
}

static void __exit rdma_exit(void)
{
	struct rdma_connection *next, *pos;

	printk(KERN_ERR "enter rdma_exit.\n");
	mutex_lock(&rdma_d.connection_lock);
	list_for_each_entry_safe(pos, next, &rdma_d.connection_list, list) {
/*		list_del_init(&pos->list);
		BUG_ON(pos->cm_id == NULL);
		printk(KERN_ERR "do disconnect 0x%p.\n", pos);
		rdma_disconnect(pos->cm_id);
		ib_drain_qp(pos->cm_id->qp);
		ib_destroy_qp(pos->cm_id->qp);
		printk(KERN_ERR "do destroy cm_id.\n");
		rdma_destroy_id(pos->cm_id);
		ib_destroy_cq(pos->cq);
		ib_dealloc_pd(pos->pd);
		kfree(pos);
*/
		INIT_WORK(&pos->disconnect_work, do_disconnect);
		schedule_work(&pos->disconnect_work);
	}
	mutex_unlock(&rdma_d.connection_lock);
	flush_scheduled_work();

	printk(KERN_ERR "destroy rdma_d.cm_id\n");
	if (rdma_d.cm_id)
		rdma_destroy_id(rdma_d.cm_id);
}

MODULE_LICENSE("GPLv2");
module_init(rdma_init);
module_exit(rdma_exit);

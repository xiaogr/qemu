/*
 * vhost-backend
 *
 * Copyright (c) 2013 Virtual Open Systems Sarl.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "hw/virtio/vhost.h"
#include "hw/virtio/vhost-backend.h"
#include "qemu/error-report.h"
#include "linux/vhost.h"

#include <sys/ioctl.h>

static int vhost_kernel_call(struct vhost_dev *dev, unsigned long int request,
                             void *arg)
{
    int fd = (uintptr_t) dev->opaque;

    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_KERNEL);

    return ioctl(fd, request, arg);
}

static int vhost_kernel_init(struct vhost_dev *dev, void *opaque)
{
    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_KERNEL);

    dev->opaque = opaque;

    return 0;
}

static int vhost_kernel_cleanup(struct vhost_dev *dev)
{
    int fd = (uintptr_t) dev->opaque;

    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_KERNEL);

    return close(fd);
}

static int vhost_kernel_get_vq_index(struct vhost_dev *dev, int idx)
{
    assert(idx >= dev->vq_index && idx < dev->vq_index + dev->nvqs);

    return idx - dev->vq_index;
}

static int vhost_kernel_memslots_limit(struct vhost_dev *dev)
{
    int limit = 64;
    char *s;

    if (g_file_get_contents("/sys/module/vhost/parameters/max_mem_regions",
                            &s, NULL, NULL)) {
        uint64_t val = g_ascii_strtoull(s, NULL, 10);
        if (!((val == G_MAXUINT64 || !val) && errno)) {
            return val;
        }
        error_report("ignoring invalid max_mem_regions value in vhost module:"
                     " %s", s);
    }
    return limit;
}

static int vhost_set_log_base(struct vhost_dev *dev, uint64_t base,
                              struct vhost_log *log)
{
    return vhost_kernel_call(dev, VHOST_SET_LOG_BASE, &base);
}

static const VhostOps kernel_ops = {
        .backend_type = VHOST_BACKEND_TYPE_KERNEL,
        .vhost_call = vhost_kernel_call,
        .vhost_backend_init = vhost_kernel_init,
        .vhost_backend_cleanup = vhost_kernel_cleanup,
        .vhost_backend_get_vq_index = vhost_kernel_get_vq_index,
        .vhost_backend_memslots_limit = vhost_kernel_memslots_limit,
        .vhost_set_log_base = vhost_set_log_base,
};

int vhost_set_backend_type(struct vhost_dev *dev, VhostBackendType backend_type)
{
    int r = 0;

    switch (backend_type) {
    case VHOST_BACKEND_TYPE_KERNEL:
        dev->vhost_ops = &kernel_ops;
        break;
    case VHOST_BACKEND_TYPE_USER:
        dev->vhost_ops = &user_ops;
        break;
    default:
        error_report("Unknown vhost backend type");
        r = -1;
    }

    return r;
}

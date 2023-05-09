/* SPDX-License-Identifier: MIT */
#define _POSIX_C_SOURCE 200112L

#include "lib.h"
#include "syscall.h"
#include "liburing.h"
#include "int_flags.h"
#include "liburing/compat.h"
#include "liburing/io_uring.h"

int io_uring_opcode_supported_panama(const struct io_uring_probe *p, int op)
{
	return io_uring_opcode_supported(p, op);
}

void io_uring_cq_advance_panama(struct io_uring *ring, unsigned nr)
{
    io_uring_cq_advance(ring, nr);
}

void io_uring_cqe_seen_panama(struct io_uring *ring, struct io_uring_cqe *cqe)
{
    io_uring_cqe_seen(ring, cqe);
}

void io_uring_sqe_set_data_panama(struct io_uring_sqe *sqe, void *data)
{
    io_uring_sqe_set_data(sqe, data);
}

void *io_uring_cqe_get_data_panama(const struct io_uring_cqe *cqe)
{
    return io_uring_cqe_get_data(cqe);
}

void io_uring_sqe_set_data64_panama(struct io_uring_sqe *sqe, __u64 data)
{
    io_uring_sqe_set_data64(sqe, data);
}

__u64 io_uring_cqe_get_data64_panama(const struct io_uring_cqe *cqe)
{
    return io_uring_cqe_get_data64(cqe);
}

void io_uring_sqe_set_flags_panama(struct io_uring_sqe *sqe, unsigned flags)
{
    io_uring_sqe_set_flags(sqe, flags);
}

void __io_uring_set_target_fixed_file_panama(struct io_uring_sqe *sqe, unsigned int file_index)
{
    __io_uring_set_target_fixed_file(sqe, file_index);
}

void io_uring_prep_rw_panama(int op, struct io_uring_sqe *sqe, int fd, const void *addr, unsigned len, __u64 offset)
{
    io_uring_prep_rw(op, sqe, fd, addr, len, offset);
}

void io_uring_prep_splice_panama(
    struct io_uring_sqe *sqe,
    int fd_in,
    int64_t off_in,
    int fd_out,
    int64_t off_out,
	unsigned int nbytes,
	unsigned int splice_flags
)
{
    io_uring_prep_splice(sqe, fd_in, off_in, fd_out, off_out, nbytes, splice_flags);
}

void io_uring_prep_tee_panama(
    struct io_uring_sqe *sqe,
    int fd_in,
    int fd_out,
    unsigned int nbytes,
    unsigned int splice_flags
)
{
    io_uring_prep_tee(sqe, fd_in, fd_out, nbytes, splice_flags);
}

void io_uring_prep_readv_panama(
    struct io_uring_sqe *sqe,
    int fd,
	const struct iovec *iovecs,
    unsigned nr_vecs,
    __u64 offset
)
{
    io_uring_prep_readv(sqe, fd, iovecs, nr_vecs, offset);
}

void io_uring_prep_readv2_panama(
    struct io_uring_sqe *sqe,
    int fd,
    const struct iovec *iovecs,
    unsigned nr_vecs,
    __u64 offset,
    int flags
)
{
    io_uring_prep_readv2(sqe, fd, iovecs, nr_vecs, offset, flags);
}

void io_uring_prep_read_fixed_panama(
    struct io_uring_sqe *sqe,
    int fd,
	void *buf,
	unsigned nbytes,
	__u64 offset,
	int buf_index
)
{
    io_uring_prep_read_fixed(sqe, fd, buf, nbytes, offset, buf_index);
}

void io_uring_prep_writev_panama(
    struct io_uring_sqe *sqe,
    int fd,
    const struct iovec *iovecs,
    unsigned nr_vecs,
    __u64 offset
)
{
    io_uring_prep_writev(sqe, fd, iovecs, nr_vecs, offset);
}

void io_uring_prep_writev2_panama(
    struct io_uring_sqe *sqe,
    int fd,
    const struct iovec *iovecs,
    unsigned nr_vecs,
    __u64 offset,
    int flags
)
{
    io_uring_prep_writev2(sqe, fd, iovecs, nr_vecs, offset, flags);
}

void io_uring_prep_write_fixed_panama(
    struct io_uring_sqe *sqe,
    int fd,
    const void *buf,
    unsigned nbytes,
    __u64 offset,
    int buf_index
)
{
    io_uring_prep_write_fixed(sqe, fd, buf, nbytes, offset, buf_index);
}

void io_uring_prep_close_panama(struct io_uring_sqe *sqe, int fd)
{
    io_uring_prep_close(sqe, fd);
}

void io_uring_prep_close_direct_panama(struct io_uring_sqe *sqe, unsigned file_index)
{
    io_uring_prep_close_direct(sqe, file_index);
}

void io_uring_prep_read_panama(struct io_uring_sqe *sqe, int fd, void *buf, unsigned nbytes, __u64 offset)
{
    io_uring_prep_read(sqe, fd, buf, nbytes, offset);
}

void io_uring_prep_write_panama(struct io_uring_sqe *sqe, int fd, const void *buf, unsigned nbytes, __u64 offset)
{
    io_uring_prep_write(sqe, fd, buf, nbytes, offset);
}

void io_uring_prep_statx_panama(
    struct io_uring_sqe *sqe,
    int dfd,
	const char *path,
	int flags,
	unsigned mask,
	struct statx *statxbuf
)
{
    io_uring_prep_statx(sqe, dfd, path, flags, mask, statxbuf);
}

void io_uring_prep_provide_buffers_panama(struct io_uring_sqe *sqe, void *addr, int len, int nr, int bgid, int bid)
{
    io_uring_prep_provide_buffers(sqe, addr, len, nr, bgid, bid);
}

void io_uring_prep_remove_buffers_panama(struct io_uring_sqe *sqe, int nr, int bgid)
{
    io_uring_prep_remove_buffers(sqe, nr, bgid);
}

void io_uring_prep_rename_panama(struct io_uring_sqe *sqe, const char *oldpath, const char *newpath)
{
    io_uring_prep_rename(sqe, oldpath, newpath);
}

void io_uring_prep_mkdir_panama(struct io_uring_sqe *sqe, const char *path, mode_t mode)
{
    io_uring_prep_mkdir(sqe, path, mode);
}

void io_uring_prep_symlink_panama(struct io_uring_sqe *sqe, const char *target, const char *linkpath)
{
    io_uring_prep_symlink(sqe, target, linkpath);
}

void io_uring_prep_link_panama(struct io_uring_sqe *sqe, const char *oldpath, const char *newpath, int flags)
{
    io_uring_prep_link(sqe, oldpath, newpath, flags);
}

unsigned io_uring_sq_ready_panama(const struct io_uring *ring)
{
    return io_uring_sq_ready(ring);
}

unsigned io_uring_sq_space_left_panama(const struct io_uring *ring)
{
    return io_uring_sq_space_left(ring);
}

int io_uring_sqring_wait_panama(struct io_uring *ring)
{
    return io_uring_sqring_wait(ring);
}

unsigned io_uring_cq_ready_panama(const struct io_uring *ring)
{
    return io_uring_cq_ready(ring);
}

bool io_uring_cq_has_overflow_panama(const struct io_uring *ring)
{
    return io_uring_cq_has_overflow(ring);
}

bool io_uring_cq_eventfd_enabled_panama(const struct io_uring *ring)
{
    return io_uring_cq_eventfd_enabled(ring);
}

int io_uring_cq_eventfd_toggle_panama(struct io_uring *ring, bool enabled)
{
    return io_uring_cq_eventfd_toggle(ring, enabled);
}

int io_uring_wait_cqe_nr_panama(struct io_uring *ring, struct io_uring_cqe **cqe_ptr, unsigned wait_nr)
{
    return io_uring_wait_cqe_nr(ring, cqe_ptr, wait_nr);
}

int __io_uring_peek_cqe_panama(struct io_uring *ring, struct io_uring_cqe **cqe_ptr, unsigned *nr_available)
{
    return __io_uring_peek_cqe(ring, cqe_ptr, nr_available);
}

int io_uring_peek_cqe_panama(struct io_uring *ring, struct io_uring_cqe **cqe_ptr)
{
    return io_uring_peek_cqe(ring, cqe_ptr);
}

int io_uring_wait_cqe_panama(struct io_uring *ring, struct io_uring_cqe **cqe_ptr)
{
    return io_uring_wait_cqe(ring, cqe_ptr);
}

struct io_uring_sqe *_io_uring_get_sqe_panama(struct io_uring *ring)
{
    return _io_uring_get_sqe(ring);
}

int io_uring_buf_ring_mask_panama(__u32 ring_entries)
{
    return io_uring_buf_ring_mask(ring_entries);
}

void io_uring_buf_ring_init_panama(struct io_uring_buf_ring *br)
{
    io_uring_buf_ring_init(br);
}

void io_uring_buf_ring_add_panama(
    struct io_uring_buf_ring *br,
    void *addr,
    unsigned int len,
	unsigned short bid,
	int mask,
	int buf_offset
)
{
    io_uring_buf_ring_add(br, addr, len, bid, mask, buf_offset);
}

void io_uring_buf_ring_advance_panama(struct io_uring_buf_ring *br, int count)
{
    io_uring_buf_ring_advance(br, count);
}

void io_uring_buf_ring_cq_advance_panama(struct io_uring *ring, struct io_uring_buf_ring *br, int count)
{
    io_uring_buf_ring_cq_advance(ring, br, count);
}

void io_uring_prep_nop_panama(struct io_uring_sqe *sqe)
{
    io_uring_prep_nop(sqe);
}
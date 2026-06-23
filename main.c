#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>
#include <vmnet/vmnet.h>

#include "cli.h"
#include "log.h"

#if __MAC_OS_X_VERSION_MAX_ALLOWED < 101500
#error "Requires macOS 10.15 or later"
#endif

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define MAX_CONNECTIONS 128
#define MAX_FRAME_SIZE (64 * 1024)
#define WRITE_BUF_SIZE (256 * 1024)
#define MAX_PACKET_COUNT_AT_ONCE 32
#define MAX_CONSECUTIVE_DROPS 1000

bool debug = false;

/* ---- Helpers ---- */

static int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0)
    return -1;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* ---- Write ring buffer ----
   All access (append by producers, drain by the consumer) is serialized by
   state.conns_lock. There are two producers — the main kqueue loop and the
   vmnet host_queue — so this is NOT a valid single-producer lock-free buffer;
   correctness comes from the mutex. The atomic indices are retained as a
   low-cost belt-and-suspenders and to document head/tail ownership. */

struct write_buf {
  uint8_t *data;
  _Atomic size_t head; /* advanced by the consumer (drain) */
  _Atomic size_t tail; /* advanced by producers (broadcast) */
  size_t capacity;
};

static int write_buf_init(struct write_buf *wb, size_t capacity) {
  wb->data = malloc(capacity);
  if (wb->data == NULL)
    return -1;
  atomic_store_explicit(&wb->head, 0, memory_order_relaxed);
  atomic_store_explicit(&wb->tail, 0, memory_order_relaxed);
  wb->capacity = capacity;
  return 0;
}

static void write_buf_destroy(struct write_buf *wb) {
  free(wb->data);
  wb->data = NULL;
}

/* Total contiguous bytes available to read (may wrap) */
static size_t write_buf_readable(struct write_buf *wb) {
  size_t head = atomic_load_explicit(&wb->head, memory_order_acquire);
  size_t tail = atomic_load_explicit(&wb->tail, memory_order_acquire);
  if (tail >= head)
    return tail - head;
  return wb->capacity - head + tail;
}

/* Total contiguous bytes available to write (may wrap) */
static size_t write_buf_writable(struct write_buf *wb) {
  size_t head = atomic_load_explicit(&wb->head, memory_order_acquire);
  size_t tail = atomic_load_explicit(&wb->tail, memory_order_acquire);
  if (tail >= head)
    return wb->capacity - (tail - head) - 1;
  return head - tail - 1;
}

/* Append bytes into the ring buffer (caller must ensure space exists) */
static void write_buf_append(struct write_buf *wb, const void *src, size_t len) {
  size_t tail = atomic_load_explicit(&wb->tail, memory_order_relaxed);
  size_t first = wb->capacity - tail;
  if (first >= len) {
    memcpy(wb->data + tail, src, len);
  } else {
    memcpy(wb->data + tail, src, first);
    memcpy(wb->data, (const uint8_t *)src + first, len - first);
  }
  size_t new_tail = tail + len;
  if (new_tail >= wb->capacity)
    new_tail -= wb->capacity;
  atomic_store_explicit(&wb->tail, new_tail, memory_order_release);
}

/* Advance head after draining bytes from the buffer */
static void write_buf_commit_drain(struct write_buf *wb, size_t len) {
  size_t head = atomic_load_explicit(&wb->head, memory_order_relaxed);
  size_t new_head = head + len;
  if (new_head >= wb->capacity)
    new_head -= wb->capacity;
  atomic_store_explicit(&wb->head, new_head, memory_order_release);
}

/* ---- vmnet helpers ---- */

static const char *vmnet_strerror(vmnet_return_t v) {
  switch (v) {
  case VMNET_SUCCESS:
    return "VMNET_SUCCESS";
  case VMNET_FAILURE:
    return "VMNET_FAILURE";
  case VMNET_MEM_FAILURE:
    return "VMNET_MEM_FAILURE";
  case VMNET_INVALID_ARGUMENT:
    return "VMNET_INVALID_ARGUMENT";
  case VMNET_SETUP_INCOMPLETE:
    return "VMNET_SETUP_INCOMPLETE";
  case VMNET_INVALID_ACCESS:
    return "VMNET_INVALID_ACCESS";
  case VMNET_PACKET_TOO_BIG:
    return "VMNET_PACKET_TOO_BIG";
  case VMNET_BUFFER_EXHAUSTED:
    return "VMNET_BUFFER_EXHAUSTED";
  case VMNET_TOO_MANY_PACKETS:
    return "VMNET_TOO_MANY_PACKETS";
  default:
    return "(unknown status)";
  }
}

static void print_vmnet_start_param(xpc_object_t param) {
  if (param == NULL)
    return;
  xpc_dictionary_apply(param, ^bool(const char *key, xpc_object_t value) {
    xpc_type_t t = xpc_get_type(value);
    if (t == XPC_TYPE_UINT64)
      INFOF("* %s: %lld", key, xpc_uint64_get_value(value));
    else if (t == XPC_TYPE_INT64)
      INFOF("* %s: %lld", key, xpc_int64_get_value(value));
    else if (t == XPC_TYPE_STRING)
      INFOF("* %s: %s", key, xpc_string_get_string_ptr(value));
    else if (t == XPC_TYPE_UUID) {
      char uuid_str[36 + 1];
      uuid_unparse(xpc_uuid_get_bytes(value), uuid_str);
      INFOF("* %s: %s", key, uuid_str);
    } else
      INFOF("* %s: (unknown type)", key);
    return true;
  });
}

/* ---- Connection and state ---- */

struct conn {
  int socket_fd;
  int active;
  uint8_t mac[6];
  /* Read state machine */
  uint8_t header_buf[4];
  int header_bytes_read;
  uint32_t expected_body_len;
  uint8_t *body_buf;
  int body_bytes_read;
  /* Write ring buffer */
  struct write_buf wbuf;
  int consecutive_drops;
};

struct state {
  int kq;
  dispatch_queue_t host_queue;
  interface_ref iface;
  uint64_t max_packet_size;
  struct conn conns[MAX_CONNECTIONS];
  int conn_count;
  /* Serializes ALL access to conns[] and every per-connection write_buf.
     Two threads touch this state: the main kqueue loop (accept / VM-socket
     read + drain) and the vmnet host_queue (RX broadcast). Held by the call
     sites in main() and _on_vmnet_packets_available(); broadcast_packet(),
     close_connection(), conn_alloc() and conn_free() assume it is held. */
  pthread_mutex_t conns_lock;
};

/* Find a free connection slot. Returns slot index or -1. */
static int conn_alloc(struct state *state) {
  for (int i = 0; i < MAX_CONNECTIONS; i++) {
    if (!state->conns[i].active) {
      state->conns[i].active = 1;
      state->conn_count++;
      return i;
    }
  }
  return -1;
}

/* Mark a connection slot as free. */
static void conn_free(struct state *state, int slot) {
  struct conn *c = &state->conns[slot];
  c->active = 0;
  state->conn_count--;
}


/* ---- Forward declarations ---- */

static void handle_vm_readable(struct state *state, int slot);
static void handle_vm_writable(struct state *state, int slot);
static void close_connection(struct state *state, int slot);
static void broadcast_packet(struct state *state, int sender_slot, const void *header, size_t header_len,
                             const void *body, size_t body_len);

/* ---- Packet broadcast (non-blocking enqueue) ---- */

static void broadcast_packet(struct state *state, int sender_slot, const void *header, size_t header_len,
                             const void *body, size_t body_len) {
  const size_t total = header_len + body_len;

  for (int i = 0; i < MAX_CONNECTIONS; i++) {
    if (i == sender_slot)
      continue;
    if (!state->conns[i].active)
      continue;

    struct conn *c = &state->conns[i];
    size_t writable = write_buf_writable(&c->wbuf);

    if (writable < total) {
      /* Backpressure: drop the packet for this VM */
      c->consecutive_drops++;
      DEBUGF("Dropping packet for fd %d: write buffer full (consecutive: %d)", c->socket_fd,
             c->consecutive_drops);
      if (c->consecutive_drops >= MAX_CONSECUTIVE_DROPS) {
        ERRORF("Too many consecutive drops for fd %d, disconnecting", c->socket_fd);
        close_connection(state, i);
      }
      continue;
    }

    c->consecutive_drops = 0;
    write_buf_append(&c->wbuf, header, header_len);
    write_buf_append(&c->wbuf, body, body_len);

    /* Enable EVFILT_WRITE so kqueue drains the buffer */
    struct kevent ev;
    EV_SET(&ev, c->socket_fd, EVFILT_WRITE, EV_ENABLE, 0, 0, (void *)(intptr_t)i);
    kevent(state->kq, &ev, 1, NULL, 0, NULL);
  }
}

/* ---- Connection lifecycle ---- */

static void close_connection(struct state *state, int slot) {
  struct conn *c = &state->conns[slot];
  INFOF("Closing connection (fd %d, slot %d)", c->socket_fd, slot);

  /* Remove from kqueue */
  struct kevent ev[2];
  EV_SET(&ev[0], c->socket_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
  EV_SET(&ev[1], c->socket_fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
  kevent(state->kq, ev, 2, NULL, 0, NULL);

  close(c->socket_fd);
  write_buf_destroy(&c->wbuf);
  free(c->body_buf);
  conn_free(state, slot);
}

static void handle_new_connection(struct state *state, int accept_fd) {
  if (set_nonblocking(accept_fd) < 0) {
    ERRORN("fcntl(O_NONBLOCK)");
    close(accept_fd);
    return;
  }

  int slot = conn_alloc(state);
  if (slot < 0) {
    ERRORF("Too many connections, rejecting fd %d", accept_fd);
    close(accept_fd);
    return;
  }

  struct conn *c = &state->conns[slot];
  c->socket_fd = accept_fd;
  c->header_bytes_read = 0;
  c->body_bytes_read = 0;
  c->expected_body_len = 0;
  c->consecutive_drops = 0;
  memset(c->mac, 0, sizeof(c->mac));

  c->body_buf = malloc(MAX_FRAME_SIZE);
  if (c->body_buf == NULL) {
    ERRORN("malloc");
    close(accept_fd);
    conn_free(state, slot);
    return;
  }

  if (write_buf_init(&c->wbuf, WRITE_BUF_SIZE) < 0) {
    ERRORN("write_buf_init");
    free(c->body_buf);
    close(accept_fd);
    conn_free(state, slot);
    return;
  }

  /* Register for read events. Write filter is added disabled. */
  struct kevent ev[2];
  EV_SET(&ev[0], accept_fd, EVFILT_READ, EV_ADD, 0, 0, (void *)(intptr_t)slot);
  EV_SET(&ev[1], accept_fd, EVFILT_WRITE, EV_ADD | EV_DISABLE, 0, 0, (void *)(intptr_t)slot);
  if (kevent(state->kq, ev, 2, NULL, 0, NULL) < 0) {
    ERRORN("kevent(EV_ADD)");
    write_buf_destroy(&c->wbuf);
    free(c->body_buf);
    close(accept_fd);
    conn_free(state, slot);
    return;
  }

  INFOF("Accepted connection (fd %d, slot %d)", accept_fd, slot);
}

/* ---- VM → Host: non-blocking read state machine ---- */

static void handle_vm_readable(struct state *state, int slot) {
  struct conn *c = &state->conns[slot];
  if (!c->active)
    return;

  for (;;) {
    /* Phase A: read the 4-byte header */
    if (c->header_bytes_read < 4) {
      ssize_t n = read(c->socket_fd, c->header_buf + c->header_bytes_read, 4 - c->header_bytes_read);
      if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
          return; /* wait for next event */
        ERRORN("read[header]");
        close_connection(state, slot);
        return;
      }
      if (n == 0) {
        INFOF("Connection closed by peer (fd %d)", c->socket_fd);
        close_connection(state, slot);
        return;
      }
      c->header_bytes_read += (int)n;
      if (c->header_bytes_read < 4)
        return; /* partial header, wait for more */
      c->expected_body_len = ntohl(*(uint32_t *)c->header_buf);
      if (c->expected_body_len > MAX_FRAME_SIZE) {
        ERRORF("Oversized frame (%u bytes) on fd %d", c->expected_body_len, c->socket_fd);
        close_connection(state, slot);
        return;
      }
    }

    /* Phase B: read the body */
    ssize_t n =
        read(c->socket_fd, c->body_buf + c->body_bytes_read, c->expected_body_len - c->body_bytes_read);
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return;
      ERRORN("read[body]");
      close_connection(state, slot);
      return;
    }
    if (n == 0) {
      INFOF("Connection closed by peer (fd %d)", c->socket_fd);
      close_connection(state, slot);
      return;
    }
    c->body_bytes_read += (int)n;
    if (c->body_bytes_read < (int)c->expected_body_len)
      return; /* partial body, wait for more */

    /* Phase C: complete packet received */
    DEBUGF("[Socket-to-VMNET] Received from fd %d: %u bytes", c->socket_fd, c->expected_body_len);

    /* Learn source MAC from Ethernet header (bytes 6-11) */
    if (c->expected_body_len >= 12) {
      memcpy(c->mac, c->body_buf + 6, 6);
    }

    /* Write to vmnet (host network) */
    struct iovec iov = {
        .iov_base = c->body_buf,
        .iov_len = c->expected_body_len,
    };
    struct vmpktdesc pd = {
        .vm_pkt_size = c->expected_body_len,
        .vm_pkt_iov = &iov,
        .vm_pkt_iovcnt = 1,
        .vm_flags = 0,
    };
    int written_count = 1;
    vmnet_return_t write_status = vmnet_write(state->iface, &pd, &written_count);
    if (write_status != VMNET_SUCCESS) {
      ERRORF("vmnet_write: [%d] %s", write_status, vmnet_strerror(write_status));
      /* Don't close — keep processing packets */
    }

    /* Flood to other VMs (non-blocking enqueue into ring buffers) */
    broadcast_packet(state, slot, c->header_buf, 4, c->body_buf, c->expected_body_len);

    /* Reset for next packet */
    c->header_bytes_read = 0;
    c->body_bytes_read = 0;
  }
}

/* ---- Write drain: non-blocking write to VM socket ---- */

static void handle_vm_writable(struct state *state, int slot) {
  struct conn *c = &state->conns[slot];
  if (!c->active)
    return;

  size_t readable = write_buf_readable(&c->wbuf);
  if (readable == 0) {
    /* Nothing to send, disable write notifications */
    struct kevent ev;
    EV_SET(&ev, c->socket_fd, EVFILT_WRITE, EV_DISABLE, 0, 0, (void *)(intptr_t)slot);
    kevent(state->kq, &ev, 1, NULL, 0, NULL);
    return;
  }

  /* Set up iovec(s) for the ring buffer (may wrap) */
  size_t head = atomic_load_explicit(&c->wbuf.head, memory_order_relaxed);
  struct iovec iov[2];
  int iovcnt = 1;
  size_t first_chunk = c->wbuf.capacity - head;
  if (first_chunk >= readable) {
    iov[0].iov_base = c->wbuf.data + head;
    iov[0].iov_len = readable;
  } else {
    iov[0].iov_base = c->wbuf.data + head;
    iov[0].iov_len = first_chunk;
    iov[1].iov_base = c->wbuf.data;
    iov[1].iov_len = readable - first_chunk;
    iovcnt = 2;
  }

  ssize_t written = writev(c->socket_fd, iov, iovcnt);
  if (written < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK)
      return; /* wait for next event */
    ERRORN("writev");
    close_connection(state, slot);
    return;
  }

  DEBUGF("[Drain] Wrote %ld bytes to fd %d", written, c->socket_fd);
  write_buf_commit_drain(&c->wbuf, (size_t)written);

  /* If buffer is now empty, disable write notifications */
  if (write_buf_readable(&c->wbuf) == 0) {
    struct kevent ev;
    EV_SET(&ev, c->socket_fd, EVFILT_WRITE, EV_DISABLE, 0, 0, (void *)(intptr_t)slot);
    kevent(state->kq, &ev, 1, NULL, 0, NULL);
  }
}

/* ---- vmnet → VMs: read from vmnet, broadcast to all sockets ---- */

static void _on_vmnet_packets_available(interface_ref iface, int64_t buf_count, int64_t max_bytes,
                                        struct state *state) {
  DEBUGF("Receiving from VMNET (buffer for %lld packets, max: %lld bytes)", buf_count, max_bytes);

  struct vmpktdesc *pdv = calloc(buf_count, sizeof(struct vmpktdesc));
  if (pdv == NULL) {
    ERRORN("calloc");
    goto done;
  }
  for (int i = 0; i < buf_count; i++) {
    pdv[i].vm_flags = 0;
    pdv[i].vm_pkt_size = max_bytes;
    pdv[i].vm_pkt_iovcnt = 1;
    pdv[i].vm_pkt_iov = malloc(sizeof(struct iovec));
    if (pdv[i].vm_pkt_iov == NULL) {
      ERRORN("malloc(sizeof(struct iovec))");
      goto done;
    }
    pdv[i].vm_pkt_iov->iov_base = malloc(max_bytes);
    if (pdv[i].vm_pkt_iov->iov_base == NULL) {
      ERRORN("malloc(max_bytes)");
      goto done;
    }
    pdv[i].vm_pkt_iov->iov_len = max_bytes;
  }

  int received_count = buf_count;
  vmnet_return_t read_status = vmnet_read(iface, pdv, &received_count);
  if (read_status != VMNET_SUCCESS) {
    ERRORF("vmnet_read: [%d] %s", read_status, vmnet_strerror(read_status));
    goto done;
  }

  DEBUGF("Received from VMNET: %d packets (buffer was prepared for %lld packets)", received_count,
         buf_count);

  pthread_mutex_lock(&state->conns_lock);
  for (int i = 0; i < received_count; i++) {
    uint32_t header_be = htonl(pdv[i].vm_pkt_size);
    broadcast_packet(state, -1, &header_be, 4, pdv[i].vm_pkt_iov[0].iov_base, pdv[i].vm_pkt_size);
  }
  pthread_mutex_unlock(&state->conns_lock);

done:
  if (pdv != NULL) {
    for (int i = 0; i < buf_count; i++) {
      if (pdv[i].vm_pkt_iov != NULL) {
        free(pdv[i].vm_pkt_iov->iov_base);
        free(pdv[i].vm_pkt_iov);
      }
    }
    free(pdv);
  }
}

static void on_vmnet_packets_available(interface_ref iface, int64_t estim_count, int64_t max_bytes,
                                       struct state *state) {
  int64_t q = estim_count / MAX_PACKET_COUNT_AT_ONCE;
  int64_t r = estim_count % MAX_PACKET_COUNT_AT_ONCE;
  DEBUGF("estim_count=%lld, dividing by MAX_PACKET_COUNT_AT_ONCE=%d; q=%lld, r=%lld", estim_count,
         MAX_PACKET_COUNT_AT_ONCE, q, r);
  for (int i = 0; i < q; i++) {
    _on_vmnet_packets_available(iface, MAX_PACKET_COUNT_AT_ONCE, max_bytes, state);
  }
  if (r > 0)
    _on_vmnet_packets_available(iface, r, max_bytes, state);
}

/* ---- vmnet start/stop ---- */

static interface_ref start(struct state *state, struct cli_options *cliopt) {
  INFOF("Initializing vmnet.framework (mode %d)", cliopt->vmnet_mode);

  vmnet_return_t st;
  vmnet_network_configuration_ref cfg = vmnet_network_configuration_create(cliopt->vmnet_mode, &st);
  struct in_addr subnet, mask;
  if(cliopt->vmnet_gateway == NULL) {
      fprintf(stderr, "vmnet_gateway is required\n");
      exit(1);
  };
  inet_aton(cliopt->vmnet_gateway, &subnet);
  inet_aton(cliopt->vmnet_mask, &mask);
  vmnet_network_configuration_set_ipv4_subnet(cfg, &subnet, &mask);
  vmnet_network_configuration_disable_dhcp(cfg);
  if (cliopt->vmnet_interface != NULL) {
    INFOF("Using external interface \"%s\"", cliopt->vmnet_interface);
    st = vmnet_network_configuration_set_external_interface(cfg, cliopt->vmnet_interface);
    if (st != VMNET_SUCCESS) {
      ERRORF("set_external_interface: [%d] %s", st, vmnet_strerror(st));
      return NULL;
    }
  }
  vmnet_network_ref net = vmnet_network_create(cfg, &st);
  if (cfg == NULL || net == NULL) {
    ERRORF("vmnet network setup: [%d] %s", st, vmnet_strerror(st));
    return NULL;
  }

  xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);

  if (cliopt->vmnet_nat66_prefix != NULL) {
    xpc_dictionary_set_string(dict, vmnet_nat66_prefix_key, cliopt->vmnet_nat66_prefix);
  }

  dispatch_semaphore_t sem = dispatch_semaphore_create(0);

  __block interface_ref iface;
  __block vmnet_return_t status;
  __block uint64_t max_bytes = 0;


  iface = vmnet_interface_start_with_network(
      net, dict, state->host_queue, ^(vmnet_return_t x_status, xpc_object_t x_param) {
        status = x_status;
        if (x_status == VMNET_SUCCESS) {
          print_vmnet_start_param(x_param);
          max_bytes = xpc_dictionary_get_uint64(x_param, vmnet_max_packet_size_key);
        }
        dispatch_semaphore_signal(sem);
      });
  dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
  xpc_release(dict);
  if (status != VMNET_SUCCESS) {
    ERRORF("vmnet_start_interface: [%d] %s", status, vmnet_strerror(status));
    return NULL;
  }

  state->max_packet_size = max_bytes;

  vmnet_interface_set_event_callback(
      iface, VMNET_INTERFACE_PACKETS_AVAILABLE, state->host_queue,
      ^(interface_event_t __attribute__((unused)) x_event_id, xpc_object_t x_event) {
        uint64_t estim_count =
            xpc_dictionary_get_uint64(x_event, vmnet_estimated_packets_available_key);
        on_vmnet_packets_available(iface, estim_count, max_bytes, state);
      });

  return iface;
}

static void stop(struct state *state, interface_ref iface) {
  if (iface == NULL) {
    return;
  }
  dispatch_semaphore_t sem = dispatch_semaphore_create(0);
  __block vmnet_return_t status;
  vmnet_stop_interface(iface, state->host_queue, ^(vmnet_return_t x_status) {
    status = x_status;
    dispatch_semaphore_signal(sem);
  });
  dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
  if (status != VMNET_SUCCESS) {
    ERRORF("vmnet_stop_interface: [%d] %s", status, vmnet_strerror(status));
  }
}

/* ---- Socket setup ---- */

static int socket_bindlisten(const char *socket_path, const char *socket_group) {
  int fd = -1;
  struct sockaddr_un addr = {0};

  unlink(socket_path); /* avoid EADDRINUSE */
  if ((fd = socket(PF_LOCAL, SOCK_STREAM, 0)) < 0) {
    ERRORN("socket");
    goto err;
  }
  if (set_nonblocking(fd) < 0) {
    ERRORN("fcntl(O_NONBLOCK) on listen socket");
    goto err;
  }
  addr.sun_family = PF_LOCAL;
  size_t socket_len = strlen(socket_path);
  if (socket_len + 1 > sizeof(addr.sun_path)) {
    ERRORF("the socket path is too long: %zu", socket_len);
    goto err;
  }
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    ERRORN("bind");
    goto err;
  }
  if (listen(fd, 0) < 0) {
    ERRORN("listen");
    goto err;
  }
  if (socket_group != NULL) {
    errno = 0;
    struct group *grp = getgrnam(socket_group); /* Do not free */
    if (grp == NULL) {
      if (errno != 0)
        ERRORN("getgrnam");
      else
        ERRORF("unknown group name \"%s\"", socket_group);
      goto err;
    }
    /* fchown can't be used (EINVAL) */
    if (chown(socket_path, -1, grp->gr_gid) < 0) {
      ERRORN("chown");
      goto err;
    }
    if (chmod(socket_path, 0770) < 0) {
      ERRORN("chmod");
      goto err;
    }
  }
  return fd;
err:
  if (fd >= 0)
    close(fd);
  return -1;
}

/* ---- Pidfile ---- */

static void remove_pidfile(const char *pidfile) {
  if (unlink(pidfile) != 0) {
    ERRORF("Failed to remove pidfile: \"%s\": %s", pidfile, strerror(errno));
    return;
  }
  INFOF("Removed pidfile \"%s\" for process %d", pidfile, getpid());
}

static int create_pidfile(const char *pidfile) {
  int flags = O_WRONLY | O_CREAT | O_EXLOCK | O_TRUNC | O_NONBLOCK;
  int fd = open(pidfile, flags, 0644);
  if (fd == -1) {
    ERRORF("Failed to open pidfile: \"%s\": %s", pidfile, strerror(errno));
    return -1;
  }

  char pid[20];
  snprintf(pid, sizeof(pid), "%u", getpid());
  ssize_t n = write(fd, pid, strlen(pid));
  if (n != (ssize_t)strlen(pid)) {
    if (n < 0) {
      ERRORF("Failed to write pidfile: \"%s\": %s", pidfile, strerror(errno));
    } else {
      ERRORF("Short write to pidfile: \"%s\"", pidfile);
    }
    remove_pidfile(pidfile);
    close(fd);
    return -1;
  }

  INFOF("Created pidfile \"%s\" for process %d", pidfile, getpid());
  return fd;
}

/* ---- Signal setup ---- */

static int setup_signals(int kq) {
  struct kevent changes[] = {
      {.ident = SIGHUP, .filter = EVFILT_SIGNAL, .flags = EV_ADD},
      {.ident = SIGINT, .filter = EVFILT_SIGNAL, .flags = EV_ADD},
      {.ident = SIGTERM, .filter = EVFILT_SIGNAL, .flags = EV_ADD},
  };

  sigset_t mask;
  sigemptyset(&mask);
  for (size_t i = 0; i < ARRAY_SIZE(changes); i++) {
    sigaddset(&mask, changes[i].ident);
  }
  if (sigprocmask(SIG_BLOCK, &mask, NULL) != 0) {
    ERRORN("sigprocmask");
    return -1;
  }

  signal(SIGPIPE, SIG_IGN);

  if (kevent(kq, changes, ARRAY_SIZE(changes), NULL, 0, NULL) != 0) {
    ERRORN("kevent");
    return -1;
  }
  return 0;
}

/* ---- Main ---- */

int main(int argc, char *argv[]) {
  debug = getenv("DEBUG") != NULL;
  int rc = 1;
  int listen_fd = -1;
  int pidfile_fd = -1;
  int kq = -1;
  __block interface_ref iface = NULL;

  struct state state = {0};
  pthread_mutex_init(&state.conns_lock, NULL);

  struct cli_options *cliopt = cli_options_parse(argc, argv);
  assert(cliopt != NULL);
  if (geteuid() != 0) {
    WARN("Running without root. This is very unlikely to work: See README.md");
  }
  if (geteuid() != getuid()) {
    WARN("Seems running with SETUID. This is insecure and highly discouraged: See README.md");
  }

  kq = kqueue();
  if (kq == -1) {
    ERRORN("kqueue");
    goto done;
  }
  state.kq = kq;

  if (setup_signals(kq)) {
    goto done;
  }

  if (cliopt->pidfile != NULL) {
    pidfile_fd = create_pidfile(cliopt->pidfile);
    if (pidfile_fd == -1) {
      goto done;
    }
  }

  DEBUGF("Opening socket \"%s\" (for UNIX group \"%s\")", cliopt->socket_path, cliopt->socket_group);
  listen_fd = socket_bindlisten(cliopt->socket_path, cliopt->socket_group);
  if (listen_fd < 0) {
    ERRORN("socket_bindlisten");
    goto done;
  }

  // Queue for processing vmnet events.
  state.host_queue = dispatch_queue_create("io.github.lima-vm.socket_vmnet.host", DISPATCH_QUEUE_SERIAL);

  iface = start(&state, cliopt);
  if (iface == NULL) {
    goto done;
  }
  state.iface = iface;

  /* Register listen socket for read events (new connections) */
  struct kevent listen_ev;
  EV_SET(&listen_ev, listen_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
  if (kevent(kq, &listen_ev, 1, NULL, 0, NULL) < 0) {
    ERRORN("kevent(listen)");
    goto done;
  }

  /* Main event loop */
  while (1) {
    struct kevent events[64];
    int n = kevent(kq, NULL, 0, events, 64, NULL);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      ERRORN("kevent");
      goto done;
    }

    for (int i = 0; i < n; i++) {
      struct kevent *ev = &events[i];

      if (ev->filter == EVFILT_SIGNAL) {
        INFOF("Received signal %s", strsignal(ev->ident));
        goto shutdown;
      }

      if (ev->filter == EVFILT_READ) {
        if ((int)ev->ident == listen_fd) {
          /* Accept all pending connections (non-blocking loop) */
          for (;;) {
            int fd = accept(listen_fd, NULL, NULL);
            if (fd < 0) {
              if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
              ERRORN("accept");
              break;
            }
            pthread_mutex_lock(&state.conns_lock);
            handle_new_connection(&state, fd);
            pthread_mutex_unlock(&state.conns_lock);
          }
        } else {
          /* Data available on a VM socket */
          int slot = (int)(intptr_t)ev->udata;
          pthread_mutex_lock(&state.conns_lock);
          handle_vm_readable(&state, slot);
          pthread_mutex_unlock(&state.conns_lock);
        }
      }

      if (ev->filter == EVFILT_WRITE) {
        int slot = (int)(intptr_t)ev->udata;
        pthread_mutex_lock(&state.conns_lock);
        handle_vm_writable(&state, slot);
        pthread_mutex_unlock(&state.conns_lock);
      }
    }
  }

shutdown:
  rc = 0;
done:
  DEBUGF("shutting down with rc=%d", rc);

  /* Close all active connections */
  pthread_mutex_lock(&state.conns_lock);
  for (int i = 0; i < MAX_CONNECTIONS; i++) {
    if (state.conns[i].active)
      close_connection(&state, i);
  }
  pthread_mutex_unlock(&state.conns_lock);

  if (iface != NULL) {
    stop(&state, iface);
  }
  if (listen_fd != -1) {
    close(listen_fd);
  }
  if (pidfile_fd != -1) {
    remove_pidfile(cliopt->pidfile);
    close(pidfile_fd);
  }
  if (state.host_queue != NULL)
    dispatch_release(state.host_queue);
  if (kq != -1) {
    close(kq);
  }
  pthread_mutex_destroy(&state.conns_lock);
  cli_options_destroy(cliopt);
  return rc;
}

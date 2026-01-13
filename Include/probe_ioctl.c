#ifndef PROBE_IOCTL_H
#define PROBE_IOCTL_H

// Shared ioctl definitions for web_probe driver and web_prober user program

// Include appropriate type definitions for kernel vs user space
#ifdef __KERNEL__
# include <linux/types.h>
#else
# include <stdint.h>
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#endif

// Magic number for ioctls (choose an unused value)
#define PROBE_IOC_MAGIC  0xB4

// Data structure for Port I/O (read/write)
struct probe_port_req {
    __u16 port;
    __u8  width;   // in bytes (1, 2, or 4)
    __u32 value;   // value read or to write
} __attribute__((packed));

// Data structure for Memory read/write (physical or kernel)
#define PROBE_MEM_MAX_LEN 256  // maximum bytes to read/write in one call
struct probe_mem_req {
    __u64 address;           // physical or kernel virtual address
    __u32 length;            // number of bytes to read/write
    __u8  data[PROBE_MEM_MAX_LEN];  // data buffer for read or write
} __attribute__((packed));

// Data structure for Hypercall request
struct probe_hcall_req {
    __u64 num;     // hypercall number
    __u64 arg1;
    __u64 arg2;
    __u64 arg3;
    __u64 result;  // return value from hypercall
} __attribute__((packed));

// Data structure for network connectivity check
struct probe_net_req {
    __u32 ip_addr;  // IPv4 address (network byte order)
    __u16 port;     // TCP port (host order)
} __attribute__((packed));

// Maximum response size for HTTP (including headers and some body, truncated if larger)
#define PROBE_HTTP_MAX_RESP 1024

// Data structure for HTTP requests
struct probe_http_req {
    __u32 ip_addr;             // IPv4 address (network order)
    __u16 port;                // port (host order, typically 80 or 443)
    __u8  use_tls;             // 0 for HTTP, 1 for HTTPS
    char  host[256];           // hostname (null-terminated)
    char  path[256];           // request path (null-terminated, e.g., "/index.html")
    __u32 resp_len;            // length of data in resp buffer
    char  resp[PROBE_HTTP_MAX_RESP];  // buffer for response data (text or binary, not necessarily null-terminated if full)
} __attribute__((packed));

// IOCTL command codes
// Use _IOWR for commands that both send input and receive output
#define PROBE_IOC_READ_PORT   _IOWR(PROBE_IOC_MAGIC, 0x01, struct probe_port_req)
#define PROBE_IOC_WRITE_PORT  _IOW (PROBE_IOC_MAGIC, 0x02, struct probe_port_req)
#define PROBE_IOC_READ_MEM    _IOWR(PROBE_IOC_MAGIC, 0x03, struct probe_mem_req)
#define PROBE_IOC_WRITE_MEM   _IOW (PROBE_IOC_MAGIC, 0x04, struct probe_mem_req)
#define PROBE_IOC_HYPERCALL   _IOWR(PROBE_IOC_MAGIC, 0x05, struct probe_hcall_req)
#define PROBE_IOC_NET_CONNECT _IOW (PROBE_IOC_MAGIC, 0x06, struct probe_net_req)
#define PROBE_IOC_HTTP_HEAD   _IOWR(PROBE_IOC_MAGIC, 0x07, struct probe_http_req)
#define PROBE_IOC_HTTP_GET    _IOWR(PROBE_IOC_MAGIC, 0x08, struct probe_http_req)

#endif // PROBE_IOCTL_H

/*
 * web_probe_drv.c - Kernel module for memory and network probing.
 * 
 * This module creates a character device (misc device "/dev/web_probe") that 
 * responds to ioctl calls defined in probe_ioctl.h. It supports:
 *   - Port I/O read/write (I/O port probing via inb/outb on x86).
 *   - Physical or kernel memory read/write (MMIO or kernel memory).
 *   - Hypercall invocation (on x86, using a VMCALL instruction; platform specific).
 *   - Network connectivity check (TCP connect to given IPv4 address/port).
 *   - Basic HTTP HEAD/GET request (TCP connect and simple HTTP request for HTTP; 
 *     for HTTPS, only connectivity is checked as TLS handshake is not implemented).
 *
 * **Note:** HTTPS handshake is not implemented in kernel (only a TCP connection to 
 * port 443 is performed). The network features use kernel socket APIs (sock_create_kern, 
 * kernel_connect, kernel_sendmsg, kernel_recvmsg)01. Memory 
 * accesses use safe kernel accessors (probe_kernel_read / copy_from_kernel_nofault) 
 * when available to avoid faults2, and ioremap/memcpy_fromio for MMIO 
 * memory access3. Use caution when reading/writing arbitrary addresses 
 * as it can crash the system if invalid.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>   // for copy_to_user, copy_from_user, probe_kernel_read
#include <linux/version.h>
#include <linux/ioctl.h>
#include <linux/io.h>        // for inb/outb, ioremap, memcpy_fromio, memcpy_toio
#include <linux/net.h>       // for sock_create_kern, kernel_connect
#include <linux/socket.h>    // for AF_INET, SOCK_STREAM
#include <net/sock.h>        // for socket operations, kernel_sendmsg, kernel_recvmsg
#include <linux/in.h>        // for sockaddr_in, IPPROTO_TCP
#include "../include/probe_ioctl.h"  // shared IOCTL codes and structs

// Compatibility for safe kernel memory access functions (Kernel >= 5.8 uses copy_*_kernel_nofault)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
# define PROBE_READ_KERNEL(dst, src, size)  copy_from_kernel_nofault((dst), (src), (size))
# define PROBE_WRITE_KERNEL(dst, src, size) copy_to_kernel_nofault((dst), (src), (size))
#else
# define PROBE_READ_KERNEL(dst, src, size)  probe_kernel_read((dst), (src), (size))
# define PROBE_WRITE_KERNEL(dst, src, size) probe_kernel_write((dst), (src), (size))
#endif

// Handler for device ioctl calls
static long web_probe_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    long ret = 0;
    // We use copy_from_user and copy_to_user to transfer data for ioctl structures.
    // Each ioctl command corresponds to a struct defined in probe_ioctl.h.
    switch (cmd) {
    case PROBE_IOC_READ_PORT: {
        struct probe_port_req req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        // Validate width (1, 2, or 4 bytes)
        if (req.width != 1 && req.width != 2 && req.width != 4) {
            return -EINVAL;
        }
#ifdef __i386__
        // 32-bit x86 I/O instructions
        if (req.width == 1)      req.value = inb(req.port);
        else if (req.width == 2) req.value = inw(req.port);
        else if (req.width == 4) req.value = inl(req.port);
#elif defined(__x86_64__)
        // 64-bit x86 uses same inb/inw/inl for port I/O
        if (req.width == 1)      req.value = inb(req.port);
        else if (req.width == 2) req.value = inw(req.port);
        else if (req.width == 4) req.value = inl(req.port);
#else
        // Port I/O not supported on other architectures
        return -ENOTSUPP;
#endif
        // Copy result back to user
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        break;
    }
    case PROBE_IOC_WRITE_PORT: {
        struct probe_port_req req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        if (req.width != 1 && req.width != 2 && req.width != 4) {
            return -EINVAL;
        }
#ifdef __i386__
        if (req.width == 1)      outb((uint8_t)req.value, req.port);
        else if (req.width == 2) outw((uint16_t)req.value, req.port);
        else if (req.width == 4) outl(req.value, req.port);
#elif defined(__x86_64__)
        if (req.width == 1)      outb((uint8_t)req.value, req.port);
        else if (req.width == 2) outw((uint16_t)req.value, req.port);
        else if (req.width == 4) outl(req.value, req.port);
#else
        return -ENOTSUPP;
#endif
        // No output data needed for write; just return success
        break;
    }
    case PROBE_IOC_READ_MEM: {
        struct probe_mem_req req;
        // Copy in the request (including desired length; data buffer will be filled by us)
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        if (req.length > PROBE_MEM_MAX_LEN) {
            return -EINVAL;  // request too large
        }
        // Attempt to read kernel memory safely
        void *addr = (void *)(uintptr_t)req.address;
        uint32_t len = req.length;
        char *kbuf = NULL;
        // First, try reading as a directly accessible kernel address range
        if (PROBE_READ_KERNEL(req.data, addr, len) != 0) {
            // Direct read failed (address likely not a normal mapped kernel address),
            // try treating the address as physical and use ioremap.
            void __iomem *iomem = ioremap((phys_addr_t)req.address, len);
            if (!iomem) {
                return -EFAULT;
            }
            // Copy from the IO-mapped memory. Use memcpy_fromio to ensure correct IO semantics4.
            memcpy_fromio(req.data, iomem, len);
            iounmap(iomem);
        }
        req.length = len; // (could be adjusted if partial read, but we assume full read or error)
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        break;
    }
    case PROBE_IOC_WRITE_MEM: {
        struct probe_mem_req req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        if (req.length > PROBE_MEM_MAX_LEN) {
            return -EINVAL;
        }
        void *addr = (void *)(uintptr_t)req.address;
        uint32_t len = req.length;
        // First, attempt direct kernel memory write
        if (PROBE_WRITE_KERNEL(addr, req.data, len) != 0) {
            // If direct write fails, try as physical memory via ioremap
            void __iomem *iomem = ioremap((phys_addr_t)req.address, len);
            if (!iomem) {
                return -EFAULT;
            }
            memcpy_toio(iomem, req.data, len);
            iounmap(iomem);
        }
        // No data to return; just break with success (0).
        break;
    }
    case PROBE_IOC_HYPERCALL: {
        struct probe_hcall_req req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
#ifdef __x86_64__
        // On x86_64, use the VMCALL instruction to trigger a hypervisor call.
        // We place the hypercall number in RAX, and arg1, arg2, arg3 in RBX, RCX, RDX.
        unsigned long rax, rbx, rcx, rdx;
        rax = req.num;
        rbx = req.arg1;
        rcx = req.arg2;
        rdx = req.arg3;
        // Note: Executing VMCALL outside of a hypervisor context may cause a crash or be undefined.
        // It's intended to be used when running inside a hypervisor that intercepts the call.
        asm volatile("mov %1, %%rax; mov %2, %%rbx; mov %3, %%rcx; mov %4, %%rdx; vmcall; mov %%rax, %0;"
                     : "=r"(rax)
                     : "r"(rax), "r"(rbx), "r"(rcx), "r"(rdx)
                     : "rax", "rbx", "rcx", "rdx");
        req.result = rax;
        // We do not handle errors from the hypercall explicitly; the hypervisor may set registers accordingly.
#else
        // Hypercall not supported on this architecture
        req.result = (uint64_t)-1;
        ret = -ENOTSUPP;
#endif
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        if (ret != 0) {
            return ret;  // return error if hypercall not supported
        }
        break;
    }
    case PROBE_IOC_NET_CONNECT: {
        struct probe_net_req req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        // Create a kernel TCP socket for IPv45.
        struct socket *sock;
        ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
        if (ret < 0) {
            return ret;  // socket creation failed
        }
        // Prepare destination address
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port   = htons(req.port),
            .sin_addr   = { .s_addr = req.ip_addr }  // ip_addr is expected in network byte order
        };
        // Connect to the target address (blocking until connect finishes or fails).
        ret = kernel_connect(sock, (struct sockaddr *)&addr, sizeof(addr), 0);
        // We don't need to send/receive any data; just checking connectivity.
        sock_release(sock);
        if (ret < 0) {
            return ret;  // return error (e.g., -ECONNREFUSED or -ETIMEDOUT)
        }
        // If ret == 0, connection successful.
        break;
    }
    case PROBE_IOC_HTTP_HEAD:
    case PROBE_IOC_HTTP_GET: {
        struct probe_http_req req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        // Ensure null-termination of host and path strings in case user input was not.
        req.host[sizeof(req.host)-1] = '\0';
        req.path[sizeof(req.path)-1] = '\0';
        // Create socket
        struct socket *sock;
        ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
        if (ret < 0) {
            return ret;
        }
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port   = htons(req.port),
            .sin_addr   = { .s_addr = req.ip_addr }  // network-order IPv4 address
        };
        ret = kernel_connect(sock, (struct sockaddr *)&addr, sizeof(addr), 0);
        if (ret < 0) {
            sock_release(sock);
            return ret;  // connection failed
        }
        if (req.use_tls) {
            // For HTTPS, we cannot perform TLS handshake here. Indicate not supported.
            sock_release(sock);
            return -EOPNOTSUPP;
        }
        // Connected over plain TCP (HTTP). Send HTTP request.
        // Build HTTP request string (use HTTP/1.0 with "Connection: close" to simplify).
        char reqbuf[512];
        const char *method = (cmd == PROBE_IOC_HTTP_HEAD ? "HEAD" : "GET");
        if (req.path[0] == '\0')
            snprintf(req.path, sizeof(req.path), "/");  // ensure path is at least "/"
        int rlen = snprintf(reqbuf, sizeof(reqbuf),
                            "%s %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
                            method, req.path, req.host);
        if (rlen < 0) {
            sock_release(sock);
            return -EFAULT;
        }
        if (rlen >= (int)sizeof(reqbuf)) {
            // Request truncated (host+path too long)
            rlen = sizeof(reqbuf) - 1;
            reqbuf[rlen] = '\0';
        }
        // Send the request over the socket6.
        struct kvec iov = { .iov_base = reqbuf, .iov_len = rlen };
        struct msghdr msg = {};
        ret = kernel_sendmsg(sock, &msg, &iov, 1, rlen);
        if (ret < 0) {
            sock_release(sock);
            return ret;
        }
        // Prepare to receive response (up to PROBE_HTTP_MAX_RESP-1 bytes so we can NULL-terminate).
        // Allocate a kernel buffer for response data.
        size_t max_resp = PROBE_HTTP_MAX_RESP;
        char *resp_buf = kzalloc(max_resp, GFP_KERNEL);
        if (!resp_buf) {
            sock_release(sock);
            return -ENOMEM;
        }
        // Receive data from socket (blocking). We attempt to read up to max_resp-1 bytes.
        struct kvec iovr = { .iov_base = resp_buf, .iov_len = max_resp - 1 };
        struct msghdr msgr = {};
        int bytes = kernel_recvmsg(sock, &msgr, &iovr, 1, max_resp - 1, 0);
        if (bytes < 0) {
            // Error receiving
            kfree(resp_buf);
            sock_release(sock);
            return bytes;
        }
        // Null-terminate the received data to make it a C-string for printing (if any space left).
        if (bytes >= 0 && bytes < max_resp)
            resp_buf[bytes] = '\0';
        else
            resp_buf[max_resp - 1] = '\0';  // ensure termination if buffer completely filled
        // Fill response length and data in the ioctl struct to return to user.
        req.resp_len = (bytes >= 0 ? (uint32_t)bytes : 0);
        // Copy at most PROBE_HTTP_MAX_RESP bytes into the struct's resp field
        if (req.resp_len > 0) {
            if (req.resp_len > PROBE_HTTP_MAX_RESP - 1)
                req.resp_len = PROBE_HTTP_MAX_RESP - 1;  // cap length to buffer size
            memcpy(req.resp, resp_buf, req.resp_len);
        }
        // Free the kernel buffer and close socket
        kfree(resp_buf);
        sock_release(sock);
        // Copy updated req (including resp data and resp_len) back to user
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        break;
    }
    default:
        return -ENOTTY;
    }
    return 0;
}

// Define file operations for the device
static struct file_operations web_probe_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = web_probe_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl   = web_probe_ioctl,  // handle 32-bit user-space if applicable
#endif
};

// Use a miscdevice for easy character device management
static struct miscdevice web_probe_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "web_probe",
    .fops  = &web_probe_fops
};

static int __init web_probe_init(void)
{
    int err = misc_register(&web_probe_dev);
    if (err) {
        pr_err("web_probe: failed to register misc device\n");
        return err;
    }
    pr_info("web_probe: module loaded, /dev/web_probe created\n");
    return 0;
}

static void __exit web_probe_exit(void)
{
    misc_deregister(&web_probe_dev);
    pr_info("web_probe: module unloaded\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ProbeTool Developer");
MODULE_DESCRIPTION("Memory and Network Probing Driver (web_probe)");
module_init(web_probe_init);
module_exit(web_probe_exit);

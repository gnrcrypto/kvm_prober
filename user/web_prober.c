/*
 * web_prober.c - User-space CLI tool for memory and network probing.
 *
 * This program interfaces with the web_probe kernel module via ioctl calls.
 * It provides a command-line interface with the following commands:
 *
 *   readport <port> [width]       - Read from I/O port (width in bytes optional, default=1).
 *   writeport <port> [width] <value> - Write value to I/O port (width optional, default=1).
 *   readmem <address> <length>    - Read <length> bytes from physical/kernel memory at <address>.
 *   writemem <address> <byte1> [byte2 ...] - Write the given byte values to memory starting at <address>.
 *   netconnect <host> <port>      - Check TCP connectivity to <host>:<port> (IPv4).
 *   httphead <URL>                - Perform an HTTP HEAD request to the given URL.
 *   httpget <URL>                 - Perform an HTTP GET request to the given URL.
 *
 * Requirements:
 *   - The kernel module (web_probe_drv.ko) must be loaded (insmod) beforehand, creating /dev/web_probe.
 *   - Run as root for port I/O and physical memory access. Network operations can be run as normal user if device permissions allow.
 *
 * Build: See Makefile (use `make` to build both the kernel module and this tool).
 * 
 * Usage examples:
 *   $ sudo insmod web_probe_drv.ko        # Load kernel module
 *   $ sudo ./web_prober readport 0x60     # Read 1 byte from port 0x60
 *   $ sudo ./web_prober writeport 0x60 0xFF 0x37  # Write 0x37 to port 0x60 (0xFF width -> 255? example misuse)
 *   $ sudo ./web_prober readmem 0x1000 16 # Read 16 bytes from physical address 0x1000
 *   $ sudo ./web_prober writemem 0x1000 0xDE 0xAD 0xBE 0xEF  # Write four bytes to memory
 *   $ ./web_prober netconnect example.com 80   # Check TCP connection to example.com:80
 *   $ ./web_prober httphead http://example.com/path
 *   $ ./web_prober httpget https://example.com   # (Will indicate HTTPS not supported for full GET)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "../include/probe_ioctl.h"  // shared ioctl definitions

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s readport <port> [width]\n"
        "  %s writeport <port> [width] <value>\n"
        "  %s readmem <address> <length>\n"
        "  %s writemem <address> <byte1> [byte2 ...]\n"
        "  %s netconnect <host> <port>\n"
        "  %s httphead <URL>\n"
        "  %s httpget <URL>\n",
        prog, prog, prog, prog, prog, prog, prog);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    const char *cmd = argv[1];
    // Open the device
    int fd = open("/dev/web_probe", O_RDWR);
    if (fd < 0) {
        perror("open /dev/web_probe");
        return 1;
    }

    int status = 0;
    if (strcmp(cmd, "readport") == 0) {
        if (argc < 3) {
            print_usage(argv[0]);
            close(fd);
            return 1;
        }
        unsigned int port = (unsigned int)strtoul(argv[2], NULL, 0);
        uint8_t width = 1;
        if (argc >= 4) {
            width = (uint8_t)strtoul(argv[3], NULL, 0);
        }
        struct probe_port_req req;
        req.port = (uint16_t)port;
        req.width = width;
        req.value = 0;
        if (ioctl(fd, PROBE_IOC_READ_PORT, &req) < 0) {
            perror("ioctl(readport)");
            status = 1;
        } else {
            printf("Port 0x%X (%u-bit) = 0x%X\n", req.port, req.width * 8, req.value);
        }
    }
    else if (strcmp(cmd, "writeport") == 0) {
        if (argc < 4) {
            print_usage(argv[0]);
            close(fd);
            return 1;
        }
        unsigned int port = (unsigned int)strtoul(argv[2], NULL, 0);
        uint8_t width = 1;
        unsigned long value;
        if (argc == 4) {
            // Only port and value provided
            value = strtoul(argv[3], NULL, 0);
        } else {
            // port, width, value
            width = (uint8_t)strtoul(argv[3], NULL, 0);
            value = strtoul(argv[4], NULL, 0);
        }
        struct probe_port_req req;
        req.port = (uint16_t)port;
        req.width = width;
        req.value = (uint32_t)value;
        if (ioctl(fd, PROBE_IOC_WRITE_PORT, &req) < 0) {
            perror("ioctl(writeport)");
            status = 1;
        } else {
            printf("Wrote 0x%X to port 0x%X (%u-bit)\n", req.value, req.port, req.width * 8);
        }
    }
    else if (strcmp(cmd, "readmem") == 0) {
        if (argc < 4) {
            print_usage(argv[0]);
            close(fd);
            return 1;
        }
        unsigned long long address = strtoull(argv[2], NULL, 0);
        unsigned int length = (unsigned int)strtoul(argv[3], NULL, 0);
        if (length > PROBE_MEM_MAX_LEN) {
            fprintf(stderr, "Length too large (max %d bytes)\n", PROBE_MEM_MAX_LEN);
            close(fd);
            return 1;
        }
        struct probe_mem_req req;
        req.address = address;
        req.length = length;
        // Initialize data buffer to zero (for safety)
        memset(req.data, 0, sizeof(req.data));
        if (ioctl(fd, PROBE_IOC_READ_MEM, &req) < 0) {
            perror("ioctl(readmem)");
            status = 1;
        } else {
            printf("Read 0x%X bytes from 0x%llX:\n", req.length, req.address);
            // Print hex dump of the data
            for (uint32_t i = 0; i < req.length; ++i) {
                if (i % 16 == 0) printf("%08llX: ", req.address + i);
                printf("%02X ", req.data[i] & 0xFF);
                if ((i % 16) == 15 || i == req.length - 1) {
                    // Print ASCII representation for the bytes on this line
                    size_t line_start = (i / 16) * 16;
                    size_t line_end = i;
                    // Fill up to 15 if this is last line and not full
                    if ((i % 16) != 15) {
                        // add spacing for alignment
                        for (size_t j = i+1; j % 16 != 0; ++j) {
                            printf("   ");
                        }
                    }
                    printf(" | ");
                    for (size_t j = line_start; j <= line_end; ++j) {
                        unsigned char c = req.data[j];
                        if (c >= 32 && c < 127)
                            printf("%c", c);
                        else
                            printf(".");
                    }
                    printf("\n");
                }
            }
        }
    }
    else if (strcmp(cmd, "writemem") == 0) {
        if (argc < 4) {
            print_usage(argv[0]);
            close(fd);
            return 1;
        }
        unsigned long long address = strtoull(argv[2], NULL, 0);
        // Byte values start from argv[3] onward
        int nbytes = argc - 3;
        if (nbytes > PROBE_MEM_MAX_LEN) {
            fprintf(stderr, "Too many bytes (max %d)\n", PROBE_MEM_MAX_LEN);
            close(fd);
            return 1;
        }
        struct probe_mem_req req;
        req.address = address;
        req.length = nbytes;
        // Parse byte values
        for (int i = 0; i < nbytes; ++i) {
            unsigned long val = strtoul(argv[3 + i], NULL, 0);
            if (val > 0xFF) {
                fprintf(stderr, "Byte value %d (0x%lX) out of 0-0xFF range\n", i, val);
                close(fd);
                return 1;
            }
            req.data[i] = (uint8_t)val;
        }
        if (ioctl(fd, PROBE_IOC_WRITE_MEM, &req) < 0) {
            perror("ioctl(writemem)");
            status = 1;
        } else {
            printf("Wrote %u bytes to 0x%llX\n", req.length, req.address);
        }
    }
    else if (strcmp(cmd, "netconnect") == 0) {
        if (argc < 4) {
            print_usage(argv[0]);
            close(fd);
            return 1;
        }
        const char *host = argv[2];
        unsigned int port = (unsigned int)strtoul(argv[3], NULL, 0);
        // Resolve host to IPv4 address
        struct in_addr ipv4;
        memset(&ipv4, 0, sizeof(ipv4));
        if (inet_aton(host, &ipv4) == 0) {
            // Not a numeric IP, try DNS resolution
            struct addrinfo hints, *res = NULL;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(host, NULL, &hints, &res) != 0) {
                fprintf(stderr, "Failed to resolve host: %s\n", host);
                close(fd);
                return 1;
            }
            if (res) {
                struct sockaddr_in *addr_in = (struct sockaddr_in *)res->ai_addr;
                ipv4 = addr_in->sin_addr;
                freeaddrinfo(res);
            } else {
                fprintf(stderr, "No IPv4 address found for host: %s\n", host);
                close(fd);
                return 1;
            }
        }
        struct probe_net_req req;
        req.ip_addr = ipv4.s_addr;  // already in network byte order
        req.port = (uint16_t)port;
        if (ioctl(fd, PROBE_IOC_NET_CONNECT, &req) < 0) {
            // If ioctl fails, errno will be set to the underlying error (ECONNREFUSED, ETIMEDOUT, etc.)
            perror("netconnect");
            status = 1;
        } else {
            printf("TCP connection to %s:%u succeeded.\n", host, port);
        }
    }
    else if (strcmp(cmd, "httphead") == 0 || strcmp(cmd, "httpget") == 0) {
        if (argc < 3) {
            print_usage(argv[0]);
            close(fd);
            return 1;
        }
        const char *url = argv[2];
        // Parse URL to extract scheme, host, port, path
        char scheme[8] = {0};
        char host[256] = {0};
        char path[256] = {0};
        uint16_t port = 0;
        uint8_t use_tls = 0;
        // Default path "/"
        strcpy(path, "/");
        const char *p = strstr(url, "://");
        const char *url_hostpart = url;
        if (p) {
            size_t schlen = p - url;
            if (schlen < sizeof(scheme)) {
                strncpy(scheme, url, schlen);
                scheme[schlen] = '\0';
            }
            url_hostpart = p + 3;
        }
        if (scheme[0] == '\0') {
            // no scheme specified, default to http
            strcpy(scheme, "http");
        }
        if (strcasecmp(scheme, "http") == 0) {
            use_tls = 0;
            port = 80;
        } else if (strcasecmp(scheme, "https") == 0) {
            use_tls = 1;
            port = 443;
        } else {
            fprintf(stderr, "Unsupported URL scheme: %s\n", scheme);
            close(fd);
            return 1;
        }
        // Separate host and path
        const char *path_start = strchr(url_hostpart, '/');
        if (path_start) {
            size_t hostlen = path_start - url_hostpart;
            if (hostlen >= sizeof(host)) hostlen = sizeof(host) - 1;
            strncpy(host, url_hostpart, hostlen);
            host[hostlen] = '\0';
            // copy the path including the leading '/'
            strncpy(path, path_start, sizeof(path) - 1);
            path[sizeof(path) - 1] = '\0';
        } else {
            // No '/' found, the entire remainder is host, use default path "/"
            strncpy(host, url_hostpart, sizeof(host) - 1);
            host[sizeof(host) - 1] = '\0';
        }
        // Check if host contains port (host:port)
        char *colon = strchr(host, ':');
        if (colon) {
            *colon = '\0';
            port = (uint16_t)strtoul(colon + 1, NULL, 0);
        }
        // Resolve host to IPv4
        struct in_addr ipv4;
        memset(&ipv4, 0, sizeof(ipv4));
        if (inet_aton(host, &ipv4) == 0) {
            struct addrinfo hints, *res = NULL;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) {
                fprintf(stderr, "Failed to resolve host: %s\n", host);
                close(fd);
                return 1;
            }
            struct sockaddr_in *addr_in = (struct sockaddr_in *)res->ai_addr;
            ipv4 = addr_in->sin_addr;
            freeaddrinfo(res);
        }
        struct probe_http_req req;
        memset(&req, 0, sizeof(req));  // zero out to initialize strings
        req.ip_addr = ipv4.s_addr;
        req.port = port;
        req.use_tls = use_tls;
        strncpy(req.host, host, sizeof(req.host) - 1);
        strncpy(req.path, path, sizeof(req.path) - 1);
        req.resp_len = 0;
        memset(req.resp, 0, sizeof(req.resp));
        unsigned long ioctl_cmd = (strcmp(cmd, "httphead") == 0 ? PROBE_IOC_HTTP_HEAD : PROBE_IOC_HTTP_GET);
        if (ioctl(fd, ioctl_cmd, &req) < 0) {
            if (errno == EOPNOTSUPP && use_tls) {
                fprintf(stderr, "HTTPS request not supported (TLS handshake not implemented in kernel). TCP connection was successful.\n");
            } else {
                perror(cmd);
            }
            status = 1;
        } else {
            // Print the HTTP response (headers and possibly content)
            if (req.resp_len > 0) {
                // Output the response bytes exactly as received (it may contain newlines or binary data)
                fwrite(req.resp, 1, req.resp_len, stdout);
                if (req.resp[req.resp_len] != '\0') {
                    // ensure output ends with newline for neatness
                    printf("\n");
                }
                if (req.resp_len >= PROBE_HTTP_MAX_RESP - 1) {
                    fprintf(stdout, "\n... (output truncated to %d bytes)\n", PROBE_HTTP_MAX_RESP - 1);
                }
            } else {
                printf("No response data received.\n");
            }
        }
    }
    else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        print_usage(argv[0]);
        status = 1;
    }

    close(fd);
    return status;
}

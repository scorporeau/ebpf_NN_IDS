#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// libbpf library header for core BPF functionality
#include <bpf/libbpf.h>

// Include our generated skeleton header (generated automatically with Makefile)
// The skeleton provides type-safe access to maps, programs, and links
#include "count_IPs_xdp.skel.h"

// Our shared definitions (same file used by eBPF program)
#include "common.h"
#include "common_usr.h"


//benchmark time, in s, 0 means no end (until ctrl+c, or kill)
static int benchmark_time = 0;


// Global flag for graceful shutdown
// Marked volatile because it's modified by signal handler
static volatile sig_atomic_t exiting = 0;


// Signal handler for graceful shutdown (Ctrl+C)
// Sets the exiting flag to stop the main event loop
static void sig_handler(int sig)
{
    // Signal number is unused but required by handler signature
    (void)sig;
    exiting = 1;
}

int main(int argc, char **argv)
{
    //parse options (benchmark time, print all)
    struct handle_event_ctx he_ctx = init_he_ctx(argc, argv, &benchmark_time);
    // print_all unused for now. But can be used for file printing, or smth else


    // pointer to our eBPF skeleton structure
    struct count_IPs_xdp_bpf *skel = NULL;
    int err;
    time_t t_start = time(NULL);

    //1
    // open bpf skeleton
    printf("Loading and attaching BPF program...\n");
    skel = count_IPs_xdp_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }


    //2
    // Load & verify BPF program
    printf("Loading BPF program...\n");
    err = count_IPs_xdp_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Error: Failed to load / verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    //3
    //attach BPF XDP to the right net interface
    printf("Attaching XDP program to network interface %s...\n", NET_INTERFACE);
    int ifindex = if_nametoindex(NET_INTERFACE);
    if (!ifindex) {
        fprintf(stderr, "Failed to find network interface name: %s\n", NET_INTERFACE);
        goto cleanup;
    }

    skel->links.xdp_trace_net_event = bpf_program__attach_xdp(skel->progs.xdp_trace_net_event, ifindex);
    if (!skel->links.xdp_trace_net_event) {
        fprintf(stderr, "Failed to attach XDP to network interface\n");
        goto cleanup;
    }


    //4
    //signal handlers for graceful shutdown !!!
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    //5
    // creating map file descriptor
    int map_fd = bpf_map__fd(skel->maps.ip_count_map);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get map fd\n");
        goto cleanup;
    }


    //infinite loop just for counting time or waiting sigkill.
    printf("Started ! Waiting for %d seconds or Ctrl+C to end...\n", benchmark_time);
    while (!exiting) {
        if (benchmark_time > 0) {
            time_t t_now = time(NULL);
            if (t_now - t_start >= benchmark_time) {
                printf("Benchmark time of %d seconds reached, exiting...\n", benchmark_time);
                break;
            }
        }
        sleep(1);
    }


cleanup:
    printf("\n...Cleaning up ...\n");

    printf("%-4s %-15s %-15s %-10s %-10s\n", "n", "Source IP", "Destination IP", "packets", "Bytes");
    printf("----------------------------------------------------------------\n");

    //loop to print every entry of the map (note that some entries might have been deleted because we are using LRU Hash maps)
    // heavily inspired by
    // https://docs.kernel.org/bpf/map_hash.html#bpf-map-type-lru-hash-and-variants

    int n = 0;
    __u64 *key = NULL;
    __u64 next_key;
    struct ip_count value;
    int err_map;

    for (;;) {
        err_map = bpf_map_get_next_key(map_fd, key, &next_key);
        if (err_map) {
            printf(" ---END--- \n");
            break; //no more entries, or error in map_fd
        }

        bpf_map_lookup_elem(map_fd, &next_key, &value);

        n ++;
        //retrieving IP addresses (NETWORK BYTE ORDER)
        __u32 src_ip = next_key >> 32;
        __u32 dst_ip = next_key & 0xFFFFFFFF;

        //printing information
        //TODO: add possibility to print to a file.
        //create source IP and dest IP strings
        char src_ip_str[16];
        char dst_ip_str[16];

        //transmitted error parsing : 0.5.18.18 + 15.18.0.X

        if ((src_ip == 0x00051212) && ((dst_ip & 0xFFFFFF00) == 0x0f120000)) { //Error IP pair
            strncpy(src_ip_str, "ERROR", sizeof(src_ip_str));
            //retrieving exact error code
            switch (dst_ip & 0xFF) {
                case 0x01:
                    strncpy(dst_ip_str, "1:TooShortEth", sizeof(dst_ip_str));
                    break;
                case 0x02:
                    strncpy(dst_ip_str, "2:NotIP", sizeof(dst_ip_str));
                    break;
                case 0x03:
                    strncpy(dst_ip_str, "3:TooShortIP", sizeof(dst_ip_str));
                    break;
                case 0xFF:
                    strncpy(dst_ip_str, "OTHER", sizeof(dst_ip_str));
                default:
                    strncpy(dst_ip_str, "UNKNOWN", sizeof(dst_ip_str));
            }
        } else {
            //classical IP parsing
            inet_ntop(AF_INET, &src_ip, src_ip_str, sizeof(src_ip_str));
            inet_ntop(AF_INET, &dst_ip, dst_ip_str, sizeof(dst_ip_str));
        }

        printf("%-4d|%-15s|%-15s|%-10llu|%-10llu\n",
            n,
            src_ip_str,
            dst_ip_str,
            value.count, value.tot_bytes);
        //next key
        key = &next_key;
    }
    printf(" %d seconds passed \n", (int)difftime(time(NULL), t_start));
}
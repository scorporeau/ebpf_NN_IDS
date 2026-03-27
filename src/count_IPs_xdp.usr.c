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
    // pointer to our eBPF skeleton structure
    struct count_IPs_xdp_bpf *skel = NULL;

    struct ring_buffer *rb = NULL;

    int err;
    
    time_t t_start = time(NULL);
    

    struct handle_event_ctx he_ctx = init_he_ctx(argc, argv, &benchmark_time);

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
    int map_fd = bpf_map__fd(skel->maps.ip_count_map);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get map fd\n");
        goto cleanup;
    }


    //infinite loop just for counting time or waiting sigkill.
    printf("Started ! Waiting fot %d seconds or Ctrl+C to end...\n", benchmark_time);
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
    printf("\n...Cleaning up after %d seconds ...\n", (int)difftime(time(NULL), t_start));


    __u64 key, next_key;
    struct ip_count value;

    printf("%-4s %-15s %-15s %-10s %-10s\n", "n", "Source IP", "Destination IP", "packets", "Bytes");
    printf("----------------------------------------------------------------\n");

    //loop to print every entry of the map (note that some entries might have been deleted because we are using LRU Hash maps)
    int n = 0;
    key = NULL;
    next_key = NULL;

    while (bpf_map_get_next_key(map_fd, &key, &next_key, sizeof(__u64)) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, sizeof(__u64), &value, sizeof(struct ip_count), NULL) == 0) {
            n ++;

            //retrieving IP addresses
            __u32 src_ip = next_key >> 32;
            __u32 dst_ip = next_key & 0xFFFFFFFF;

            //printing information
            //TODO: add possibility to print to a file.
            printf("%-4d %-3u.%-3u.%-3u.%-3u %-3u.%-3u.%-3u.%-3u %-10llu %-10llu\n",
                n,
                /* IP source */
                (src_ip) & 0xFF,
                (src_ip >> 8) & 0xFF,
                (src_ip >> 16) & 0xFF,
                (src_ip >> 24) & 0xFF,
                /* IP dest */
                (dst_ip) & 0xFF,
                (dst_ip >> 8) & 0xFF,
                (dst_ip >> 16) & 0xFF,
                (dst_ip >> 24) & 0xFF,
                value.count, value.tot_bytes);
        }
        key = next_key;
    }

}
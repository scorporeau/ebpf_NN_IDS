#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <net/if.h>

// libbpf library header for core BPF functionality
#include <bpf/libbpf.h>

// Include our generated skeleton header (generated automatically with Makefile)
// The skeleton provides type-safe access to maps, programs, and links
#include "net_listener_xdp.skel.h"

// Our shared definitions (same file used by eBPF program)
#include "common.h"

// true = printing all packets, false = just counting them. Note that the bpf program is still sending full information to the user space.
const bool printPackets = true;

//benchmark time, in s, 0 means no end (until ctrl+c, or kill)
static int benchmark_time = 0;




// Global flag for graceful shutdown
// Marked volatile because it's modified by signal handler
static volatile sig_atomic_t exiting = 0;

int n_events = 0;

// Signal handler for graceful shutdown (Ctrl+C)
// Sets the exiting flag to stop the main event loop
static void sig_handler(int sig)
{
    // Signal number is unused but required by handler signature
    (void)sig;
    exiting = 1;
}


// Callback function invoked for each event from the ring buffer
// This is called by libbpf's ring buffer polling mechanism
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;

    const struct netevent *e = data;

    n_events++;

    if (data_sz < sizeof(*e)) {
        fprintf(stderr, "Error: event size mismatch\n");
        return 0;
    }

    // Determine protocol string
    char protocol_str[16];
    if (e->protocol == 6) {
        strcpy(protocol_str, "TCP");
    } else if (e->protocol == 17) {
        strcpy(protocol_str, "UDP");
    } else {
        snprintf(protocol_str, sizeof(protocol_str), "%u", e->protocol);
    }

    if (printPackets) {
        //print informations (the IPs with dots for readability)
        printf("%-4i %-3u.%-3u.%-3u.%-3u:%-8u %-3u.%-3u.%-3u.%-3u:%-8u %-8s %-8u %-8u\n",
            n_events,
            (e->src_ip) & 0xFF,
            (e->src_ip >> 8) & 0xFF,
            (e->src_ip >> 16) & 0xFF,
            (e->src_ip >> 24) & 0xFF,
            e->src_port,
            (e->dst_ip) & 0xFF,
            (e->dst_ip >> 8) & 0xFF,
            (e->dst_ip >> 16) & 0xFF,
            (e->dst_ip >> 24) & 0xFF,
            e->dst_port,
            protocol_str,
            e->packet_size,
            e->pid);
    } else {
        printf("%-4i\n", n_events);
    }

    return 0;
}


int main(int argc, char **argv)
{
    // pointer to our eBPF skeleton structure
    struct net_listener_xdp_bpf *skel = NULL;

    struct ring_buffer *rb = NULL;

    int err;
    
    time_t t_start = time(NULL);
    

    //initializing benchmark time if provided as argument
    if (argc > 1) {
        benchmark_time = atoi(argv[1]);
        if (benchmark_time < 0) {
            fprintf(stderr, "Invalid benchmark time: %s\n", argv[1]);
            return 1;
        }
    }



    //1
    // open bpf skeleton
    skel = net_listener_xdp_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }


    //2
    // Load & verify BPF program
    err = net_listener_xdp_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Error: Failed to load / verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    //3
    //attach BPF XDP to the right net interface
    int ifindex = if_nametoindex(NET_INTERFACE);
    if (!ifindex) {
        fprintf(stderr, "Failed to find network interface name: %s\n", NET_INTERFACE);
        goto cleanup;
    }

    skel->links.xdp_trace_net_event =
        bpf_program__attach_xdp(skel->progs.xdp_trace_net_event, ifindex);
    if (!skel->links.xdp_trace_net_event) {
        fprintf(stderr, "Failed to attach XDP to network interface\n");
        goto cleanup;
    }


    //4
    //signal handlers for graceful shutdown !!!
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);


    //5
    // empty the ring buffer2) & process data
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events_ring),
                            handle_event,
                            NULL,
                            NULL);
    
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    if (printPackets) {
        //header printing, then let the handle_event function do its work
        printf("%-4s %-15s:%-8s %-15s:%-8s %-8s %-8s %-8s\n","n", "ipS", "portS","ipD","portD","prot","size","pid");
    } else {
        printf("%-4s\n", "N");
    }
    

    //"infinite" loop to listen to the ring
    while (!exiting) {
        // Poll with 200ms timeout
        // Returns number of events consumed, or negative on error
        err = ring_buffer__poll(rb, 200 /* timeout in ms */);

        // Handle interruption by signal
        if (err == -EINTR) {
            err = 0;
            break;
        }

        // Handle actual errors
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
        // err > 0 means we processed that many events (handlea d by callback)

        if (benchmark_time!=0 && difftime(time(NULL), t_start) > benchmark_time) {
            printf("Benchmark time of %is reached.\n", benchmark_time);
            break;
        }
    }

cleanup:
    printf("\n...Cleaning up ...\n");
    // Clean up resources in reverse order of creation

    // Free the ring buffer
    ring_buffer__free(rb);

    // Destroy the skeleton (detaches programs, closes maps)
    net_listener_xdp_bpf__destroy(skel);

    return err < 0 ? 1 : 0;

}
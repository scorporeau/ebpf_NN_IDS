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
#include "common_usr_net_listener.h"


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
    time_t t_start = time(NULL);
    // pointer to our eBPF skeleton structure
    struct net_listener_xdp_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;
    /* Track interface and attach state so we can detach on cleanup */
    int ifindex = 0;
    unsigned int xdp_flags = (1U << 1);//XDP_FLAGS_SKB_MODE
    struct parameters params = init_params(argc, argv);


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
    ifindex = if_nametoindex(NET_INTERFACE);
    if (!ifindex) {
        fprintf(stderr, "Failed to find network interface name: %s\n", NET_INTERFACE);
        goto cleanup;
    }

    /* Use bpf_program__fd + bpf_set_link_xdp_fd to attach with flags so the
     * chosen attach mode is respected. Store attached state to detach later.
     */
    int prog_fd = bpf_program__fd(skel->progs.xdp_trace_net_event);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get BPF program fd\n");
        goto cleanup;
    }

    //attach XDP program to the interface & with right flags (driver, skb, offload)
    err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL);

    //4
    //signal handlers for graceful shutdown !!!
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    #ifndef SILENT
    //5
    // empty the ring buffer2) & process data
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events_ring),print_netevent,&params,NULL);
    
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    //5bis : retrieve drop rb array file descriptor
    int dc_fd = bpf_map__fd(skel->maps.drop_counter);
    if (dc_fd < 0) {
        fprintf(stderr, "Failed to get drop counter map fd\n");
        goto cleanup;
    }

    //6 print header
    print_netevent_header(params);
    #endif
    

    //"infinite" loop
    while (!exiting) {
        #ifndef SILENT
        //listen to rungbuf
        // Poll with 200ms timeout
        // Returns number of events consumed, or negative on error
        err = ring_buffer__poll(rb, TIMEOUT_RINGBUF_POLL /* timeout in ms */);

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
        #endif

        if (params.benchmark_time!=0 && difftime(time(NULL), t_start) > params.benchmark_time) {
            printf("Benchmark time of %is reached.\n", params.benchmark_time);
            break;
        }
    }

cleanup:
    printf("\n...Cleaning up after %d seconds ...\n", (int)difftime(time(NULL), t_start));
    // Clean up resources in reverse order of creation

    #ifndef SILENT
    // Free the ring buffer
    ring_buffer__free(rb);

    if (dc_fd) {
        // print drop counters, with descriptions:
        __u32 keys[] = {0, 1, 2, 3, 4, 5, 6};
        const char *descriptions[] = {
            "Ringbuf full",
            "Too short for eth header",
            "Not IP",
            "Packet too short for IP header",
            "Packet too short for TCP header",
            "Packet too short for UDP header",
            "Other parsing error"
        };
        printf("\nDrop counters:\n");
        for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); i++) {
            __u64 cnt;
            if (bpf_map_lookup_elem(dc_fd, &keys[i], &cnt) >= 0) {
                printf("  %s: %llu\n", descriptions[i], cnt);
            }
        }

    }
    #endif
    // Destroy the skeleton (detaches programs, closes maps)
    bpf_xdp_detach(ifindex, xdp_flags, NULL);
    net_listener_xdp_bpf__destroy(skel);

    return err < 0 ? 1 : 0;

}
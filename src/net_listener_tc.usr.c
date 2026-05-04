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
#include "net_listener_tc.skel.h"

// Our shared definitions (same file used by eBPF program)
#include "common_usr_net_listener.h" //also includes common.h


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
    struct net_listener_tc_bpf *skel = NULL;

    struct ring_buffer *rb = NULL;

    int err;
    
    time_t t_start = time(NULL);

    struct parameters params = init_params(argc, argv);


    //1
    // open bpf skeleton
    skel = net_listener_tc_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }


    //2
    // Load & verify BPF program
    err = net_listener_tc_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Error: Failed to load / verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    //3
    //attach TC BPF via tcx
    int ifindex = if_nametoindex(NET_INTERFACE);
    if (!ifindex) {
        fprintf(stderr, "Failed to find network interface name: %s\n", NET_INTERFACE);
        goto cleanup;
    }

    skel->links.tc_trace_net_event = bpf_program__attach_tcx(skel->progs.tc_trace_net_event, ifindex, NULL);
    if (!skel->links.tc_trace_net_event) {
        fprintf(stderr, "Failed to attach TCX program\n");
        goto cleanup;
    }

    //4
    //signal handlers for graceful shutdown !!!
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    //5
    // create ring buffer to receive events from the kernel
    #ifndef SILENT
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events_ring),print_netevent,&params,NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    #endif    

    //6
    //create map counting dropped packets (not dropped, but not passed through the ring buffer)
    #ifndef SILENT
    int dc_fd = -1;
    dc_fd = bpf_map__fd(skel->maps.drop_counter);
    if (dc_fd < 0) {
        fprintf(stderr, "Failed to get drop counter map fd\n");
        goto cleanup;
    }
    #endif

    // print the header
    print_netevent_header(params);


    //7
    //infinite loop
    while (!exiting) {
        //listen to the ring buffer
        #ifndef SILENT
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
        // err > 0 means we processed that many events (handled by callback)
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
    if (rb != NULL) {
        ring_buffer__free(rb);
    }
    //output the # of packets not passed trough the ring buffer
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
    net_listener_tc_bpf__destroy(skel);

    return err < 0 ? 1 : 0;

}
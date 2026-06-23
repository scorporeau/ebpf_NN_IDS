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
#include "dummy_xdp.skel.h"
#include "common.h"



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

int main(int argc, char const *argv[])
{
    struct dummy_xdp_bpf *skel = NULL;
    int err;
    int ifindex = 0;
    __u32 xdp_flags = (1U << 1);//XDP_FLAGS_SKB_MODE



    //1
    // open bpf skeleton
    skel = dummy_xdp_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }


    //2
    // Load & verify BPF program
    err = dummy_xdp_bpf__load(skel);
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
    int prog_fd = bpf_program__fd(skel->progs.xdp_dummy);
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

    while (!exiting) {
        // Wait for signal
        pause();
    }

cleanup:
    // Destroy the skeleton (detaches programs, closes maps)
    bpf_xdp_detach(ifindex, xdp_flags, NULL);
    dummy_xdp_bpf__destroy(skel);

    return 0;
}


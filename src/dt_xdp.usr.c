// User space code for running the decision tree.

//This program should be able to load the decision tree in the array in order to transmit it to the decision tree XDP program.
//It can eventually print the log of decisions taken with the boolean DEBUG in ml_dt.h (but it might affect performance)


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>



//libbpf library
#include <bpf/libbpf.h>

// Include our generated skeleton header (generated automatically with Makefile)
// The skeleton provides type-safe access to maps, programs, and links
#include "dt_xdp.skel.h"

//common libraries
#include "common.h"
#include "common_usr.h"
#include "ml_dt.h"


// Global flag for graceful shutdown
// Marked volatile because it's modified by signal handler
static volatile sig_atomic_t exiting = 0;
static int benchmark_time = 0;


// Signal handler for graceful shutdown (Ctrl+C)
// Sets the exiting flag to stop the main event loop
static void sig_handler(int sig)
{
    // Signal number is unused but required by handler signature
    (void)sig;
    exiting = 1;
}

static void print_log(void *ctx, void *data, size_t data_sz)
{
    struct debug_info *d = data;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &d->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &d->dst_ip, dst_ip, sizeof(dst_ip));
    printf("%-15s:%-5d|%-15s:%-5d|%-8d|%-6d|%-5s\n", src_ip, d->src_port, dst_ip, d->dst_port, d->protocol, d->packet_size, d->decision ? "PASS" : "DROP");
}

//Fill the decision tree nodes structure located in the bpf array that the bpf program uses for IDS decision making.
static int fill_dt_nodes_array(int dt_nodes_array_fd, struct dt_node *dt_nodes_array)
{
    for (int i = 0; i < DT_NODE_NB; i++) {
        if (bpf_map_update_elem(dt_nodes_array_fd, &i, &dt_nodes_array[i], BPF_ANY) != 0) {
            fprintf(stderr, "Error updating decision tree nodes array map at index %d: %s\n", i, strerror(errno));
            return -1;
        }
    }
    return 0;
}

//update parameters and store them in the array (that will be later sent tot the kernel space)
static void retrieve_dt_parameters(const char *filename, struct dt_node *dt_nodes_array)
{
    //create a basic DT that drops UDP packets, and pass everything else. Just for testing purposes.
    //the structure is the following :
    /*
                root : feature = protocol, thresh = 16.
                /                       \
                <=16                      >16
               /                           \
            PASS              node 2: feature = protocol, thresh = 17
                                    /               \
                               ==17                  > 17
                                /                       \
                            DROP                        PASS
    */
    dt_nodes_array[0] = (struct dt_node) {
        //root node in the graph
        .feature = 0b11000010, //feature 2 (protocol), pass left, defined node
        .threshold = 16
    };
    dt_nodes_array[2] = (struct dt_node) {
        //node 2 in the graph
        .feature = 0b01000010, //feature 2, pass right, defined node.
        .threshold = 17
    };

}

int main(int argc, char const **argv)
{
    struct dt_xdp_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;
    time_t t_start = time(NULL);
    init_he_ctx(argc, argv, &benchmark_time); //fill benchmark time

    //1
    //open, load and attach XDP bpf program.
    //open
    skel = dt_xdp_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    //load
    err = dt_xdp_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Error: Failed to load / verify BPF skeleton: %d\n", err);
        goto cleanup;
    }
    //attach to interface
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

    //2
    //signal handlers for graceful shutdown !!!
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    //create ring buffer for debug logs
    if (DEBUG) {
        rb = ring_buffer__new(bpf_map__fd(skel->maps.events_ring),print_log,NULL,NULL);
        if (!rb) {
            fprintf(stderr, "Failed to create ring buffer\n");
            goto cleanup;
        }
        //print table header
        printf("%-15s:%-5s|%-15s:%-5s|%-8s|%-6s|%-5s\n", "SRC_IP", "PORT", "DST_IP", "PORT", "PROTOC","SIZE", "Dec?");
    }

    //create LRU hash map & decision tree nodes array.
    int map_fd = bpf_map__fd(skel->maps.flow_info_map);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get map fd\n");
        goto cleanup;
    }
    int dt_nodes_array_fd = bpf_map__fd(skel->maps.dt_nodes_array);
    if (dt_nodes_array_fd < 0) {
        fprintf(stderr, "Failed to get decision tree nodes array map fd\n");
        goto cleanup;
    }

    //fill decision tree nodes
    //create array of dt nodes later filled by a function reading parameters from a file outputed by pytorch)
    struct dt_node dt_nodes_array[DT_NODE_NB];
    retrieve_dt_parameters("filename.csv", dt_nodes_array);
    if (fill_dt_nodes_array(dt_nodes_array_fd, dt_nodes_array)) {
        fprintf(stderr, "Failed to fill decision tree nodes array\n");
        goto cleanup;
    }

    //main loop
    printf("Started ! Waiting for %d seconds or Ctrl+C to end...\n", benchmark_time);
    while (!exiting) {
        //pull ring buffer and handle exceptions or end of benchmark time.
        if (DEBUG) {
            err = ring_buffer__poll(rb, TIMEOUT_RINGBUF_POLL /* timeout in ms */);
        }
        if (err == -EINTR) {
            err = 0;
            exiting = 1;
        } else if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            exiting = 1;
        } else if (benchmark_time > 0) {
            time_t t_now = time(NULL);
            if (t_now - t_start >= benchmark_time) {
                printf("Benchmark time of %d seconds reached, exiting...\n", benchmark_time);
                exiting = 1;
            }
        }
        sleep(1);
    }





cleanup:
    printf("\n...Cleaning up after %d seconds ...\n", (int)difftime(time(NULL), t_start));
    // Clean up resources in reverse order of creation
    if (DEBUG) {
        // Free the ring buffer
        ring_buffer__free(rb);
    }
    //the flow hash map & decision tree nodes array will be freed by skeleton destruction.
    // Destroy the skeleton (detaches programs, closes maps)
    dt_xdp_bpf__destroy(skel);
    return 0;
}

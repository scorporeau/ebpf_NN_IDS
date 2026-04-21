//include/common_usr.h - common user-space definitions shared between user-space scripts (mostly printing functions)

#ifndef __COMMON_USR_H
#define __COMMON_USR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <net/if.h>
#include <arpa/inet.h>


#include "common.h"


#define TIMEOUT_RINGBUF_POLL 50 //ms, timeout for ring buffer wait in case of empty buffer.
//#define PRINT_ALL true //print all packet information, or only the packet numbers (used only in user-space)


//struct for print_netevent context. Contains print all boolean and number of events processed
struct handle_event_ctx {
    int n_events;
    const bool print_all;
};

//initializer for handle_event_ctx
struct handle_event_ctx init_he_ctx(int argc, char **argv, int *benchmark_time) {
    bool print_all = false;
    int n_events = 0;
    //initializing benchmark time if provided as argument
    if (argc == 2) {
        print_all = atoi(argv[1]) != 0;
    }
    else if (argc == 3) {
        *benchmark_time = atoi(argv[2]);
        if (*benchmark_time < 0) {
            fprintf(stderr, "Invalid benchmark time: %s\n", argv[2]);
            *benchmark_time = 0;
        }
        print_all = atoi(argv[1]) != 0;
    } else {
        print_all = false;
        *benchmark_time = 0;
    }
    return (struct handle_event_ctx) {
        .n_events = n_events,
        .print_all = print_all
    };
}

//print netevent header once before printing everything else.
static void print_netevent_header(bool printall)
{
    if (printall) {
        //header printing, then let the print_netevent function do its work
        printf("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n","n", "ipS", "portS","ipD","portD","protocol","size","time_parsing", "time_class","time_total");
    } else {
        printf("%-4s %-15s:%-8s %-15s:%-8s %-8s %-8s|%-8s %-8s %-8s\n","n", "ipS", "portS","ipD","portD","prot","size","parsing", "class","total(ns)");
    }
}

//handle recieving network event function (prints packet info on terminal)
static int print_netevent(void *ctx, void *data, size_t data_sz)
{

    const struct netevent *e = data;

    //add 1 to n_events which is contained in the context
    struct handle_event_ctx *event_ctx = (struct handle_event_ctx *)ctx;
    event_ctx->n_events++;

    if (data_sz < sizeof(*e)) {
        fprintf(stderr, "Error: event size mismatch\n");
        return 0;
    }
    /*
    // Determine protocol string
    char protocol_str[16];
    if (e->protocol == 6) {
        strcpy(protocol_str, "TCP");
    } else if (e->protocol == 17) {
        strcpy(protocol_str, "UDP");
    } else {
        snprintf(protocol_str, sizeof(protocol_str), "%u", e->protocol);
    }
    */

    //ip to string conversion
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &e->dst_ip, dst_ip, sizeof(dst_ip));

    if (event_ctx->print_all) {
        //print informations (the IPs with dots for readability)
        printf("%i,%s,%u,%s,%u,%u,%u,%u,%u,%u\n",
            event_ctx->n_events,
            src_ip,
            e->src_port,
            dst_ip,
            e->dst_port,
            e->protocol,
            e->packet_size,
            e->t_parsing,
            e->t_classification,
            e->t_tot);
    } else {
        printf("%-4i %-15s:%-8u %-15s:%-8u %-8u %-8u|%-8u %-8u %-8u\n",
            event_ctx->n_events,
            src_ip,
            e->src_port,
            dst_ip,
            e->dst_port,
            e->protocol,
            e->packet_size,
            e->t_parsing,
            e->t_classification,
            e->t_tot);
    }

    return 0;
}

#endif /* __COMMON_USR_H */
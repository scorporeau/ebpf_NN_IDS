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
struct parameters {
    //script parameters
    const bool print_csv;
    const int benchmark_time;
    const bool print_times;
    //global variables
    int n_events;
};

//initializer for parameters
struct parameters init_params(int argc, char **argv) {
    //if help
    if (strcmp(argv[1], "--help") == 0) {
        printf("Usage: %s [print_csv] [benchmark_time] [print_times]\n", argv[0]);
        printf("  print_csv: 0 (default) for human-readable output, 1 for CSV format\n");
        printf("  benchmark_time: duration in seconds to run the program (default: 0 for infinite)\n");
        printf("  print_times: 1 (default) for timing info, 0 for no timing info\n");
        exit(0);
    }

    //else :
    bool print_csv = false;
    bool print_times = true;
    int benchmark_time = 0;

    //initializing benchmark time if provided as argument
    if (argc > 0) {
        print_csv = atoi(argv[1]) != 0;
    }
    if (argc > 1) {
        benchmark_time = atoi(argv[2]);
    }
    if (argc > 2) {
        print_times = atoi(argv[3]) != 0;
    }
    return (struct parameters) {
        .print_csv = print_csv,
        .benchmark_time = benchmark_time,
        .print_times = print_times,
        .n_events = 0
    };
}

//print netevent header once before printing everything else.
static void print_netevent_header(struct parameters params)
{
    if (params.print_csv && params.print_times) {
        //header printing, then let the print_netevent function do its work
        printf("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n","n", "ipS", "portS","ipD","portD","protocol","size","time_parsing", "time_class","time_total");
    } else if (params.print_csv && !params.print_times) {
        
    } else if (!params.print_csv && params.print_times) {
        printf("%-4s %-15s:%-8s %-15s:%-8s %-8s %-8s|%-8s %-8s %-8s\n","n", "ipS", "portS","ipD","portD","prot","size","parsing", "class","total(ns)");
    } else { // no csv no times
        printf("%-4s %-15s:%-8s %-15s:%-8s %-8s %-8s\n","n", "ipS", "portS","ipD","portD","prot","size");
    }
}

//handle recieving network event function (prints packet info on terminal)
static int print_netevent(void *params, void *data, size_t data_sz)
{

    const struct netevent *e = data;
    struct parameters *p = params;
    p->n_events++; //add 1 to the # of events processed

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

    if (p->print_csv && p->print_times) {
        printf("%i,%s,%u,%s,%u,%u,%u,%u,%u,%u\n",
            p->n_events,
            src_ip,
            e->src_port,
            dst_ip,
            e->dst_port,
            e->protocol,
            e->packet_size,
            e->t_parsing,
            e->t_classification,
            e->t_tot);
    } else if (!p->print_csv && p->print_times) {
        printf("%-4i %-15s:%-8u %-15s:%-8u %-8u %-8u|%-8u %-8u %-8u\n",
            p->n_events,
            src_ip,
            e->src_port,
            dst_ip,
            e->dst_port,
            e->protocol,
            e->packet_size,
            e->t_parsing,
            e->t_classification,
            e->t_tot);
    } else if (p->print_csv && !p->print_times) {
        printf("%i,%s,%u,%s,%u,%u,%u\n",
            p->n_events,
            src_ip,
            e->src_port,
            dst_ip,
            e->dst_port,
            e->protocol,
            e->packet_size);
    } else { //no csv, no times
        printf("%-4i %-15s:%-8u %-15s:%-8u %-8u %-8u\n",
            p->n_events,
            src_ip,
            e->src_port,
            dst_ip,
            e->dst_port,
            e->protocol,
            e->packet_size);
    }

    return 0;
}

#endif /* __COMMON_USR_H */
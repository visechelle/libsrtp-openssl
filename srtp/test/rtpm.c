/*
 * rtpm.c
 *
 * rtp multi-threaded sender/receiver
 *
 * John A. Foley
 * Cisco Systems, Inc.
 *
 * This app is a simple RTP application intended only for testing
 * libsrtp.  It creates multiple RTP sessions and either sends
 * or receives data on each session.  Each session operates in it's
 * own thread. This is written to run on Linux using pthreads.
 *
 *
 * Copyright (c) 2012, Cisco Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include "datatypes.h"

#include <stdio.h>          /* for printf, fprintf */
#include <stdlib.h>         /* for atoi()          */
#include <errno.h>
#include <unistd.h>         /* for close()         */
#include <string.h>         /* for strncpy()       */
#include <time.h>           /* for usleep()        */
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "srtp.h"
#include "rtp.h"


#define NUM_SSRC_PER_THREAD 10
#define THREAD_PKT_CNT      100000

#define MAX_THREADS_SUPPORTED 10

#define SSRC_BASE        0xBEEF0000
#define ADDR_IS_MULTICAST(a) IN_MULTICAST(htonl(a))
#define MAX_KEY_LEN      64
#define MASTER_KEY_LEN   30
#define STAT_WINDOW      1000
#define DATA_LEN         256
#define SLEEP_LEN        1000  /* how busy should we keep these threads? */

char test_data[DATA_LEN] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
};

int thread_status[MAX_THREADS_SUPPORTED];
static pthread_mutex_t t_mutex = PTHREAD_MUTEX_INITIALIZER;

FILE *output;

typedef struct thread_parms {
    pthread_t thread_id;        /* ID returned by pthread_create() */
    int thread_num;
    int sock;
    int port;
    srtp_policy_t *policy;
    struct sockaddr_in name;
    uint32_t ssrc;
    int stream_cnt;
} thread_parms_t;

/*
 * the function usage() prints an error message describing how this
 * program should be called, then calls exit()
 */
void usage (char *string)
{
    printf("usage: %s -k <key> -n <num_threads>  "
           "[-s | -r] dest_ip dest_port_start\n"
           "where  \n"
           "       -k <key>  sets the srtp master key\n"
           "       -s act as rtp sender\n"
           "       -r act as rtp receiver\n"
           "       -o <filename>  Send output to file when receiver\n",
           string);
    exit(1);
}



void * receiver_thread (void *arg)
{
    err_status_t status;
    rtp_receiver_t rcvr[NUM_SSRC_PER_THREAD];
    int cnt = 0;
    thread_parms_t *tp = (thread_parms_t*)arg;
    int len = DATA_LEN;
    char data[DATA_LEN + RTP_HEADER_LEN + 20]; //Adding 20 bytes for UDP header???
    srtp_ctx_t *srtp_ctx = NULL;
    int i;

    printf("\nStarting receiver thread (port: %d  base-ssrc: %x  stream_cnt: %d)\n",
           tp->port, tp->ssrc, tp->stream_cnt);

    if (bind(tp->sock, (struct sockaddr*)&tp->name, sizeof(tp->name)) < 0) {
        close(tp->sock);
        pthread_mutex_lock(&t_mutex);
        fprintf(output, "receiver socket bind error\n");
        fflush(output);
        pthread_mutex_unlock(&t_mutex);
        perror(NULL);
        exit(1);
    }

    status = srtp_create(&srtp_ctx, tp->policy);
    if (status) {
        pthread_mutex_lock(&t_mutex);
        fprintf(output,
                "error: srtp_create() failed with code %d\n",
                status);
        fflush(output);
        pthread_mutex_unlock(&t_mutex);
        exit(1);
    }

    /* now add the streams on the session */
    for (i = 0; i < tp->stream_cnt; i++) {
        rtp_receiver_init(&rcvr[i], tp->sock, tp->name, tp->ssrc);
        rcvr[i].srtp_ctx = srtp_ctx;
        status = srtp_add_stream(rcvr[i].srtp_ctx, tp->policy);
        if (status) {
            pthread_mutex_lock(&t_mutex);
            fprintf(output,
                    "error: srtp_add_stream() failed with code %d\n",
                    status);
            fflush(output);
            pthread_mutex_unlock(&t_mutex);
            exit(1);
        }
        tp->policy->ssrc.value++;
        tp->ssrc++;
    }


    /* get next packet and loop */
    while (cnt < THREAD_PKT_CNT) {
        len = DATA_LEN + RTP_HEADER_LEN + 20;
        if (rtp_recvfrom(&rcvr[0], data, &len) > -1) {
            cnt++;
            if (cnt % STAT_WINDOW == 0) {
                pthread_mutex_lock(&t_mutex);
                fprintf(output, "Thread id %d receive count is %d\n", tp->thread_num, cnt);
                fflush(output);
                pthread_mutex_unlock(&t_mutex);
            }
        }
    }

    /*
     * Clean up the session
     */
    srtp_dealloc(srtp_ctx);

    return (NULL);
}

void * sender_thread (void *arg)
{
    err_status_t status;
    thread_parms_t *tp = (thread_parms_t*)arg;
    rtp_sender_t snd[NUM_SSRC_PER_THREAD];
    int cnt = 0;
    int i;
    srtp_ctx_t *srtp_ctx = NULL;

    printf("\nStarting sender thread (port: %d  base-ssrc: %x  stream_cnt: %d)\n",
           tp->port, tp->ssrc, tp->stream_cnt);

    /* initialize sender's rtp and srtp contexts */
    status = srtp_create(&srtp_ctx, tp->policy);
    if (status) {
        fprintf(stderr,
                "error: srtp_create() failed with code %d\n",
                status);
        exit(1);
    }

    /* now add the streams on the session */
    for (i = 0; i < tp->stream_cnt; i++) {
        rtp_sender_init(&snd[i], tp->sock, tp->name, tp->ssrc);
        snd[i].srtp_ctx = srtp_ctx;
        status = srtp_add_stream(snd[i].srtp_ctx, tp->policy);
        if (status) {
            fprintf(stderr,
                    "error: srtp_add_stream() failed with code %d\n",
                    status);
            exit(1);
        }
        tp->policy->ssrc.value++;
        tp->ssrc++;
    }

    while (cnt < THREAD_PKT_CNT) {
        for (i = 0; i < tp->stream_cnt; i++) {
            rtp_sendto(&snd[i], test_data, DATA_LEN);
            cnt++;
            if (cnt % STAT_WINDOW == 0) {
                printf("Thread id %d transmit count is %d\n", tp->thread_num, cnt);
            }
        }
        usleep(SLEEP_LEN);
    }


    /*
     * Clean up the session
     */
    srtp_dealloc(srtp_ctx);

    return NULL;
}

/*
 * program_type distinguishes the [s]rtp sender and receiver cases
 */
typedef enum { sender, receiver, unknown } program_type;


/*
 * Here's the entry point
 */
int main (int argc, char *argv[])
{
    int sock;
    char *filenm = NULL;
    struct in_addr rcvr_addr;
    program_type prog_type = unknown;
    sec_serv_t sec_servs = sec_serv_conf | sec_serv_auth;
    int num_threads = 1;
    int c;
    char *input_key = NULL;
    char *address = NULL;
    char key[MAX_KEY_LEN];
    unsigned short start_port = 0;
    srtp_policy_t *policy;
    err_status_t status;
    thread_parms_t *tplist[MAX_THREADS_SUPPORTED];
    thread_parms_t *tp;
    int i;
    pthread_attr_t t_attr;
    struct sched_param sp1 = { 11 };
    int len;
    int rc;

    /* initialize srtp library */
    status = srtp_init();
    if (status) {
        printf("error: srtp initialization failed with error code %d\n", status);
        exit(1);
    }

    /* check args */
    while (1) {
        c = getopt(argc, argv, "k:n:o:rs");
        if (c == -1) {
            break;
        }
        switch (c) {
        case 'n':
            num_threads = atoi(optarg);
            if (num_threads > MAX_THREADS_SUPPORTED) {
                printf("error: maximum number of threads supported is %d\n", MAX_THREADS_SUPPORTED);
                exit(1);
            }
            printf("Running %d threads\n", num_threads);
            break;
        case 'k':
            input_key = optarg;
            printf("Using key\n");
            break;
        case 'o':
            filenm = optarg;
            printf("Using output file: %s\n", filenm);
            break;
        case 'r':
            prog_type = receiver;
            break;
        case 's':
            prog_type = sender;
            break;
        default:
            usage(argv[0]);
        }
    }

    if (prog_type == unknown) {
        printf("error: neither sender [-s] nor receiver [-r] specified\n");
        usage(argv[0]);
    }

    if (!input_key) {
        /*
         * a key must be provided if and only if security services have
         * been requested
         */
        usage(argv[0]);
    }

    if (argc != optind + 2) {
        /* wrong number of arguments */
        usage(argv[0]);
    }

    /* get IP address from arg */
    address = argv[optind++];

    /*
     * read key from hexadecimal on command line into an octet string
     */
    len = hex_string_to_octet_string(key, input_key, MASTER_KEY_LEN * 2);

    /* check that hex string is the right length */
    if (len < MASTER_KEY_LEN * 2) {
        fprintf(stderr,
                "error: too few digits in key/salt "
                "(should be %d hexadecimal digits, found %d)\n",
                MASTER_KEY_LEN * 2, len);
        exit(1);
    }
    if (strlen(input_key) > MASTER_KEY_LEN * 2) {
        fprintf(stderr,
                "error: too many digits in key/salt "
                "(should be %d hexadecimal digits, found %u)\n",
                MASTER_KEY_LEN * 2, (unsigned)strlen(input_key));
        exit(1);
    }

    printf("set master key/salt to %s/", octet_string_hex_string(key, 16));
    printf("%s\n", octet_string_hex_string(key + 16, 14));


    /* get starting port from arg */
    start_port = atoi(argv[optind++]);

    /* set address */
    rcvr_addr.s_addr = inet_addr(address);
    if (0xffffffff == rcvr_addr.s_addr) {
        fprintf(stderr, "%s: cannot parse IP v4 address %s\n", argv[0], address);
        exit(1);
    }

    if (ADDR_IS_MULTICAST(rcvr_addr.s_addr)) {
        printf("\nMulticast addresses not supported\n");
        exit(1);
    }

    if (prog_type == receiver && filenm != NULL) {
        output = fopen(filenm, "wa");
        if (output == NULL) {
            printf("\nUnable to open output file.\n");
            exit(1);
        }
    } else {
        output = stdout;
    }

    /*
     * Setup and kick-off each thread.  Each thread will be either
     * a receiver or a sender, depending on the arguments passed to us
     */
    for (i = 0; i < num_threads; i++) {
        /* open socket */
        sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) {
            int err;
            err = errno;
            fprintf(stderr, "%s: couldn't open socket: %d\n", argv[0], err);
            exit(1);
        }

        /*
         * Create an SRTP policy
         */
        policy = malloc(sizeof(srtp_policy_t));
        if (policy == NULL) {
            fprintf(stderr, "Unable to malloc\n");
            exit(1);
        }

        crypto_policy_set_rtp_default(&policy->rtp);
        crypto_policy_set_rtcp_default(&policy->rtcp);
        policy->ssrc.type  = ssrc_specific;
        policy->ssrc.value = SSRC_BASE;
        policy->key  = (uint8_t*)key;
        policy->next = NULL;
        policy->rtp.sec_serv = sec_servs;
        policy->rtcp.sec_serv = sec_serv_none;  /* we don't do RTCP anyway */

        /*
         * Create a thread_parms_t instance to manage this thread
         */
        tplist[i] = malloc(sizeof(thread_parms_t));
        if (tplist[i] == NULL) {
            fprintf(stderr, "Unable to malloc\n");
            exit(1);
        }
        tp = tplist[i];

        tp->thread_num = i;
        tp->sock = sock;
        tp->port = start_port + i;
        tp->policy = policy;
        tp->name.sin_addr   = rcvr_addr;
        tp->name.sin_family = PF_INET;
        tp->name.sin_port   = htons(start_port + i);
        tp->ssrc = SSRC_BASE;
        tp->stream_cnt = NUM_SSRC_PER_THREAD; //Number of streams to create for the session


        /*
         * Setup the pthread attributes
         */
        pthread_attr_init(&t_attr);
        pthread_attr_setschedparam(&t_attr, &sp1);
        pthread_attr_setschedpolicy(&t_attr, SCHED_RR);

        if (prog_type == sender) {
            /*
             * Start a sender thread
             */
            rc = pthread_create(&tp->thread_id, &t_attr, sender_thread, tp);
            if (rc) {
                fprintf(stderr, "Unable to create thread\n");
                exit(1);
            }
        } else { /* prog_type == receiver */
            /*
             * Start a receiver thread
             */
            rc = pthread_create(&tp->thread_id, &t_attr, receiver_thread, tp);
            if (rc) {
                fprintf(stderr, "Unable to create thread\n");
                exit(1);
            }
        }
        /*
         * Clean-up the attributes
         */
        pthread_attr_destroy(&t_attr);
    }


    /*
     * Wait for all threads to finish
     */
    for (i = 0; i < num_threads; i++) {
        void *res;
        tp = tplist[i];
        pthread_join(tp->thread_id, &res);
        close(tplist[i]->sock);
        free(tplist[i]->policy);
        free(tplist[i]);
    }

    /*
     * If we don't call this, we get a memory leak in the
     * libsrtp libary
     */
    status = srtp_shutdown();
    if (status) {
	printf("error: srtp shutdown failed with error code %d\n", status);
	exit(1);
    }

    return (0);
}





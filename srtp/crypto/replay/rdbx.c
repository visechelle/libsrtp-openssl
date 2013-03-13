/*
 * rdbx.c
 *
 * a replay database with extended range, using a rollover counter
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 */

/*
 *
 * Copyright (c) 2001-2005,2012, Cisco Systems, Inc.
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

#include "rdbx.h"


/*
 * from draft-ietf-avt-srtp-00.txt:
 *
 * A receiver reconstructs the index i of a packet with sequence
 *  number s using the estimate
 *
 * i = 65,536 * t + s,
 *
 * where t is chosen from the set { r-1, r, r+1 } such that i is
 * closest to the value 65,536 * r + s_l.  If the value r+1 is used,
 * then the rollover counter r in the cryptographic context is
 * incremented by one (if the packet containing s is authentic).
 */



/*
 * rdbx implementation notes
 *
 * A xtd_seq_num_t is essentially a sequence number for which some of
 * the data on the wire are implicit.  It logically consists of a
 * rollover counter and a sequence number; the sequence number is the
 * explicit part, and the rollover counter is the implicit part.
 *
 * Upon receiving a sequence_number (e.g. in a newly received SRTP
 * packet), the complete xtd_seq_num_t can be estimated by using a
 * local xtd_seq_num_t as a basis.  This is done using the function
 * index_guess(&local, &guess, seq_from_packet).  This function
 * returns the difference of the guess and the local value.  The local
 * xtd_seq_num_t can be moved forward to the guess using the function
 * index_advance(&guess, delta), where delta is the difference.
 *
 *
 * A rdbx_t consists of a xtd_seq_num_t and a bitmask.  The index is highest
 * sequence number that has been received, and the bitmask indicates
 * which of the recent indicies have been received as well.  The
 * highest bit in the bitmask corresponds to the index in the bitmask.
 */


void
index_init (xtd_seq_num_t *pi)
{
#ifdef NO_64BIT_MATH
    *pi = make64(0, 0);
#else
    *pi = 0;
#endif
}

void
index_advance (xtd_seq_num_t *pi, sequence_number_t s)
{
#ifdef NO_64BIT_MATH
    /* a > ~b means a+b will generate a carry */
    /* s is uint16 here */
    *pi = make64(high32(*pi) + (s > ~low32(*pi) ? 1 : 0), low32(*pi) + s);
#else
    *pi += s;
#endif
}


/*
 * index_guess(local, guess, s)
 *
 * given a xtd_seq_num_t local (which represents the last
 * known-to-be-good received xtd_seq_num_t) and a sequence number s
 * (from a newly arrived packet), sets the contents of *guess to
 * contain the best guess of the packet index to which s corresponds,
 * and returns the difference between *guess and *local
 *
 * nota bene - the output is a signed integer, DON'T cast it to a
 * unsigned integer!
 */

int
index_guess (const xtd_seq_num_t *local,
             xtd_seq_num_t *guess,
             sequence_number_t s)
{
#ifdef NO_64BIT_MATH
    uint32_t local_roc = ((high32(*local) << 16) |
                          (low32(*local) >> 16));
    uint16_t local_seq = (uint16_t)(low32(*local));
#else
    uint32_t local_roc = (uint32_t)(*local >> 16);
    uint16_t local_seq = (uint16_t)*local;
#endif
#ifdef NO_64BIT_MATH
    uint32_t guess_roc = ((high32(*guess) << 16) |
                          (low32(*guess) >> 16));
    uint16_t guess_seq = (uint16_t)(low32(*guess));
#else
    uint32_t guess_roc = (uint32_t)(*guess >> 16);
    uint16_t guess_seq = (uint16_t)*guess;
#endif
    int difference;

    if (local_seq < seq_num_median) {
        if (s - local_seq > seq_num_median) {
            guess_roc = local_roc - 1;
	    difference = s - local_seq - seq_num_max;
	} else {
            guess_roc = local_roc;
            difference = s - local_seq;
        }
    } else {
        if (local_seq - seq_num_median > s) {
            guess_roc = local_roc + 1;
	    difference = s - local_seq + seq_num_max;
        } else {
            guess_roc = local_roc;
            difference = s - local_seq;
        }
    }
    guess_seq = s;

    /* Note: guess_roc is 32 bits, so this generates a 48-bit result! */
#ifdef NO_64BIT_MATH
    *guess = make64(guess_roc >> 16,
                    (guess_roc << 16) | guess_seq);
#else
    *guess = (((uint64_t)guess_roc) << 16) | guess_seq;
#endif

    return difference;
}

/*
 * rdbx
 *
 */


/*
 *  rdbx_init(&r, ws) initializes the rdbx_t pointed to by r with window size ws
 */
err_status_t
rdbx_init(rdbx_t *rdbx, unsigned long ws) {
    if (ws == 0) {
	return err_status_bad_param;
    }

    if (bitvector_alloc(&rdbx->bitmask, ws) != 0) {
	return err_status_alloc_fail;
    }

    index_init(&rdbx->index);

    return err_status_ok;
}

/*
 *  rdbx_dealloc(&r) frees memory for the rdbx_t pointed to by r
 */
err_status_t
rdbx_dealloc(rdbx_t *rdbx) {
    bitvector_dealloc(&rdbx->bitmask);

    return err_status_ok;
}

/*
 * rdbx_get_window_size(rdbx) returns the value of the window size
 * for the rdbx_t pointed to by rdbx
 * 
 */
unsigned long
rdbx_get_window_size(const rdbx_t *rdbx) {
    return bitvector_get_length(&rdbx->bitmask);
}


/*
 * rdbx_check(&r, delta) checks to see if the xtd_seq_num_t
 * which is at rdbx->index + delta is in the rdb
 */

err_status_t
rdbx_check(const rdbx_t *rdbx, int delta) 
{
    if (delta > 0) {       
	/* if delta is positive, it's good */
	return err_status_ok;
    } else if ((int)(bitvector_get_length(&rdbx->bitmask) - 1) + delta < 0) {   
        /* if delta is lower than the bitmask, it's bad */
	return err_status_replay_old; 
    } else if (bitvector_get_bit(&rdbx->bitmask, 
	        (int)(bitvector_get_length(&rdbx->bitmask) - 1) + delta) == 1) {
        /* delta is within the window, so check the bitmask */
	return err_status_replay_fail;    
    }

    /* otherwise, the index is okay */
    return err_status_ok; 
}

/*
 * rdbx_add_index adds the xtd_seq_num_t at rdbx->window_start + d to
 * replay_db (and does *not* check if that xtd_seq_num_t appears in db)
 *
 * this function should be called only after replay_check has
 * indicated that the index does not appear in the rdbx, e.g., a mutex
 * should protect the rdbx between these calls if need be
 */

err_status_t
rdbx_add_index (rdbx_t *rdbx, int delta)
{

    if (delta > 0) {
        /* shift forward by delta */
        index_advance(&rdbx->index, delta);
	bitvector_left_shift(&rdbx->bitmask, delta);
	bitvector_set_bit(&rdbx->bitmask, 
		bitvector_get_length(&rdbx->bitmask) - 1);        
    } else {
        /* delta is in window */
	bitvector_set_bit(&rdbx->bitmask, 
		bitvector_get_length(&rdbx->bitmask) -1 + delta);
    }

    /* note that we need not consider the case that delta == 0 */

    return err_status_ok;
}



/*
 * rdbx_estimate_index(rdbx, guess, s)
 *
 * given an rdbx and a sequence number s (from a newly arrived packet),
 * sets the contents of *guess to contain the best guess of the packet
 * index to which s corresponds, and returns the difference between
 * *guess and the locally stored synch info
 */

int
rdbx_estimate_index (const rdbx_t *rdbx,
                     xtd_seq_num_t *guess,
                     sequence_number_t s)
{

    /*
     * if the sequence number and rollover counter in the rdbx are
     * non-zero, then use the index_guess(...) function, otherwise, just
     * set the rollover counter to zero (since the index_guess(...)
     * function might incorrectly guess that the rollover counter is
     * 0xffffffff)
     */

#ifdef NO_64BIT_MATH
    /* seq_num_median = 0x8000 */
    if (high32(rdbx->index) > 0 ||
        low32(rdbx->index) > seq_num_median)
#else
    if (rdbx->index > seq_num_median)
#endif
    { return index_guess(&rdbx->index, guess, s); }

#ifdef NO_64BIT_MATH
    *guess = make64(0, (uint32_t)s);
#else
    *guess = s;
#endif

#ifdef NO_64BIT_MATH
    return s - (uint16_t)low32(rdbx->index);
#else
    return s - (uint16_t)rdbx->index;
#endif
}

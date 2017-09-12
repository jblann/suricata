/* Copyright (C) 2015 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \ingroup decode
 *
 * @{
 */


/**
 * \file
 *
 * \author XXX Your Name <your@email.com>
 *
 * Decodes XXX describe the protocol
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "decode-events.h"
#include "decode-udplite.h"

#include "util-unittest.h"
#include "util-debug.h"

/**
 * \brief Function to decode XXX packets
 * \param tv thread vars
 * \param dtv decoder thread vars
 * \param p packet
 * \param pkt raw packet data
 * \param len length in bytes of pkt array
 * \retval TM_ECODE_OK or TM_ECODE_FAILED on serious error
 */

int DecodeUDPLITE(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                   const uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    /* TODO add counter for your type of packet to DecodeThreadVars,
     * and register it in DecodeRegisterPerfCounters */
    //StatsIncr(tv, dtv->counter_udplite);

    /* Validation: make sure that the input data is big enough to hold
     *             the header */
    if (len < sizeof(UdpliteHdr)) {
        /* in case of errors, we set events. Events are defined in
         * decode-events.h, and are then exposed to the detection
         * engine through detect-engine-events.h */
        ENGINE_SET_INVALID_EVENT(p,UDPLITE_HEADER_TOO_SMALL);
        //ENGINE_SET_EVENT(p,UDPLITE_HEADER_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    /* Now we can access the header */
    UdpliteHdr *hdr = (UdpliteHdr *)pkt;
    p->udpliteh = hdr;

    //SET_UDP_SRC_PORT(p,&p->sp);
    //SET_UDP_DST_PORT(p,&p->dp);

    SCLogNotice("UDP LITE: sport=%d dport=%d", ntohs(hdr->sport), ntohs(hdr->dport));

    if (ntohs(hdr->coverage) != 0 && ntohs(hdr->coverage) < 8) {
        SCLogNotice("UDP LITE: Setting invalid coverage event.");
        ENGINE_SET_INVALID_EVENT(p, UDPLITE_INVALID_COVERAGE);
        //ENGINE_SET_EVENT(p, UDPLITE_INVALID_COVERAGE);
    }

    return TM_ECODE_OK;
}

/**
 * @}
 */

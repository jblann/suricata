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
 * \file DHCP application layer detector and parser.
 *
 * \author Tom DeCanio <decanio.tom@gmail.com>
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"

#include "util-print.h"
#include "util-unittest.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "app-layer-dhcp.h"

//#define PRINT

/* The default port to probe for echo traffic if not provided in the
 * configuration file. */
#define DHCP_DEFAULT_SERVER_PORT "67"
#define DHCP_DEFAULT_CLIENT_PORT "68"

#define DHCP_MIN_FRAME_LEN 232

/* Enum of app-layer events for an echo protocol. Normally you might
 * have events for errors in parsing data, like unexpected data being
 * received. For echo we'll make something up, and log an app-layer
 * level alert if an empty message is received.
 *
 * Example rule:
 *
 * alert dhcp any any -> any any (msg:"SURCATA dhcp empty message"; \
 *    app-layer-event:dhcp.empty_message; sid:X; rev:Y;)
 */
enum {
    DHCP_DECODER_EVENT_EMPTY_MESSAGE,
};

SCEnumCharMap dhcp_decoder_event_table[] = {
    {"EMPTY_MESSAGE", DHCP_DECODER_EVENT_EMPTY_MESSAGE},
};

static uint32_t dhcp_config_max_transactions = 32;

static DHCPState dhcpGlobalState;

static void DHCPTxFree(DHCPState *dhcp, void *tx, uint32_t locked)
{
    DHCPTransaction *dhcptx = tx;

    if (dhcptx->request_buffer != NULL)
        SCFree(dhcptx->request_buffer);

    if (dhcptx->response_buffer != NULL)
        SCFree(dhcptx->response_buffer);

    if (dhcptx->decoder_events != NULL)
        AppLayerDecoderEventsFreeEvents(&dhcptx->decoder_events);

    if (dhcptx->de_state != NULL)
        DetectEngineStateFree(dhcptx->de_state);

    SCFree(tx);

    if (unlikely(locked == 0)) {
        SCMutexLock(&dhcp->lock);
    }
    dhcp->transaction_count++;
    if (unlikely(locked == 0)) {
        SCMutexUnlock(&dhcp->lock);
    }
}

static DHCPTransaction *DHCPTxAlloc(DHCPState *dhcp)
{
    DHCPTransaction *tx;

    /* limit outstanding transactions */
    SCMutexLock(&dhcp->lock);
    if (unlikely(dhcp->transaction_count > dhcp_config_max_transactions)) {
        /* toss out the oldest */
        tx = TAILQ_FIRST(&dhcp->tx_list);
        if (likely(tx != NULL)) {
            TAILQ_REMOVE(&dhcp->tx_list, tx, next);
            DHCPTxFree(dhcp, tx, 1);
        }
    }
    SCMutexUnlock(&dhcp->lock);

    tx = SCCalloc(1, sizeof(DHCPTransaction));
    if (unlikely(tx == NULL)) {
        return NULL;
    }

    SCMutexLock(&dhcp->lock);

    /* Increment the transaction ID on the state each time one is
     * allocated. */
    tx->tx_id = dhcp->transaction_max++;
    dhcp->transaction_count++;

    TAILQ_INSERT_TAIL(&dhcp->tx_list, tx, next);

    SCMutexUnlock(&dhcp->lock);

    return tx;
}

static SC_ATOMIC_DECLARE(uint64_t, DHCPStateAllocCount);

static void *DHCPStateAlloc(void)
{
    /* TBD: possibly make this per vlan */
    DHCPState *state = &dhcpGlobalState;

    if (SC_ATOMIC_CAS(&state->initialized, 0, 1) == 1) {
        SCMutexInit(&state->lock, NULL);
        TAILQ_INIT(&state->tx_list);
        SC_ATOMIC_INIT(DHCPStateAllocCount);
    }
    SC_ATOMIC_ADD(DHCPStateAllocCount, 1);
    return state;
}

static void DHCPStateFree(void *state)
{
    DHCPState *dhcp_state = state;
    DHCPTransaction *tx;
    uint64_t count = SC_ATOMIC_SUB(DHCPStateAllocCount, 1);
    /* free in-flight transactions with last DHCPStateFree */
    if (count == 0) {
        SCMutexLock(&dhcp_state->lock);
        while ((tx = TAILQ_FIRST(&dhcp_state->tx_list)) != NULL) {
            TAILQ_REMOVE(&dhcp_state->tx_list, tx, next);
            DHCPTxFree(dhcp_state, tx, 1);
        }
        SCMutexUnlock(&dhcp_state->lock);
    }
}

/**
 * \brief Callback from the application layer to have a transaction freed.
 *
 * \param state a void pointer to the dhcpState object.
 * \param tx_id the transaction ID to free.
 */
static void DHCPStateTxFree(void *state, uint64_t tx_id)
{
    DHCPState *dhcp = state;
    DHCPTransaction *tx = NULL, *ttx;

    SCLogDebug("Freeing transaction %"PRIu64, tx_id);

    SCMutexLock(&dhcp->lock);
    TAILQ_FOREACH_SAFE(tx, &dhcp->tx_list, next, ttx) {

        /* Continue if this is not the transaction we are looking
         * for. */
        if (tx->tx_id != tx_id) {
            continue;
        }

        /* Remove and free the transaction. */
        TAILQ_REMOVE(&dhcp->tx_list, tx, next);
        DHCPTxFree(dhcp, tx, 1);

        SCMutexUnlock(&dhcp->lock);
        return;
    }
    SCMutexUnlock(&dhcp->lock);

    SCLogDebug("Transaction %"PRIu64" not found.", tx_id);
}

static int DHCPStateGetEventInfo(const char *event_name, int *event_id,
    AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, dhcp_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "DHCP enum map table.",  event_name);
        /* This should be treated as fatal. */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static AppLayerDecoderEvents *DHCPGetEvents(void *state, uint64_t tx_id)
{
    DHCPState *dhcp_state = state;
    DHCPTransaction *tx;

    SCMutexLock(&dhcp_state->lock);
    TAILQ_FOREACH(tx, &dhcp_state->tx_list, next) {
        if (tx->tx_id == tx_id) {
            SCMutexUnlock(&dhcp_state->lock);
            return tx->decoder_events;
        }
    }
    SCMutexUnlock(&dhcp_state->lock);

    return NULL;
}

static int DHCPHasEvents(void *state)
{
    DHCPState *echo = state;
    return echo->events;
}

static DHCPTransaction *DHCPGetTxByXid(void *state, uint32_t xid)
{
    DHCPState *dhcp = state;
    DHCPTransaction *tx, *ttx;

    SCLogDebug("Requested tx XID %"PRIu32".", xid);

    SCMutexLock(&dhcp->lock);
    TAILQ_FOREACH_SAFE(tx, &dhcp->tx_list, next, ttx) {
        if (tx->logged) {
            /* Remove and free the transaction. */
            TAILQ_REMOVE(&dhcp->tx_list, tx, next);
            DHCPTxFree(dhcp, tx, 1);
            continue;
        }
        if (tx->xid == xid) {
            SCMutexUnlock(&dhcp->lock);
            SCLogDebug("Transaction %"PRIu32" found, returning tx object %p.",
                xid, tx);
            return tx;
        }
    }
    SCMutexUnlock(&dhcp->lock);

    SCLogDebug("Transaction ID %"PRIu32" not found.", xid);

    return NULL;
}

/**
 * \brief Probe the input to see if it looks like echo.
 *
 * \retval ALPROTO_DHCP if it looks like echo, otherwise
 *     ALPROTO_UNKNOWN.
 */
static AppProto DHCPToServerProbingParser(uint8_t *input, uint32_t input_len,
    uint32_t *offset)
{
    /* TBD: have the infrastructure call us back with the flow struct *
     * so that we can check that this arrived on the proper 5 tuple
     */
    //PrintRawDataFp(stdout, input, input_len);

    if (input_len >= DHCP_MIN_FRAME_LEN) {
        BOOTPHdr *bootp = (BOOTPHdr *)input;

        if ((bootp->op == BOOTP_REQUEST) &&
            (bootp->htype == BOOTP_ETHERNET) &&
            (bootp->hlen == 6) &&
            (bootp->magic == ntohl(BOOTP_DHCP_MAGIC_COOKIE))) {
            DHCPOpt *dhcp = (DHCPOpt *)(input + sizeof(BOOTPHdr));

            if ((dhcp->code == DHCP_DHCP_MSG_TYPE) &&
                (dhcp->len == 1)) {

                SCLogDebug("Detected as ALPROTO_DHCP.");
                return ALPROTO_DHCP;
            }
        }
    }

    SCLogDebug("Protocol not detected as ALPROTO_DHCP.");
    return ALPROTO_UNKNOWN;
}

/**
 * \brief Probe the input to see if it looks like echo.
 *
 * \retval ALPROTO_DHCP if it looks like echo, otherwise
 *     ALPROTO_UNKNOWN.
 */
static AppProto DHCPToClientProbingParser(uint8_t *input, uint32_t input_len,
    uint32_t *offset)
{
    /* TBD: have the infrastructure call us back with the flow struct *
     * so that we can check that this arrived on the proper 5 tuple
     */
    //PrintRawDataFp(stdout, input, input_len);

    if (input_len >= DHCP_MIN_FRAME_LEN) {
        BOOTPHdr *bootp = (BOOTPHdr *)input;

        if ((bootp->op == BOOTP_REPLY) &&
            (bootp->htype == BOOTP_ETHERNET) &&
            (bootp->hlen == 6) &&
            (bootp->magic == ntohl(BOOTP_DHCP_MAGIC_COOKIE))) {
            DHCPOpt *dhcp = (DHCPOpt *)(input + sizeof(BOOTPHdr));

            if ((dhcp->code == DHCP_DHCP_MSG_TYPE) &&
                (dhcp->len == 1)) {

                SCLogDebug("Detected as ALPROTO_DHCP.");
                return ALPROTO_DHCP;
            }
        }
    }

    SCLogDebug("Protocol not detected as ALPROTO_DHCP.");
    return ALPROTO_UNKNOWN;
}

static int DHCPParse(Flow *f, void *state,
    AppLayerParserState *pstate, uint8_t *input, uint32_t input_len,
    void *local_data)
{
    DHCPState *dhcp_state = state;

    /* Likely connection closed, we can just return here. */
    if ((input == NULL || input_len == 0) &&
        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        return 0;
    }

    /* Probably don't want to create a transaction in this case
     * either. */
    if (input == NULL || input_len == 0) {
        return 0;
    }

    /* Normally you would parse out data here and store it in the
     * transaction object, but as this is echo, we'll just record the
     * request data. */

    if (input_len >= DHCP_MIN_FRAME_LEN) {
        BOOTPHdr *bootp = (BOOTPHdr *)input;

        if ((bootp->op == BOOTP_REQUEST) &&
            (bootp->htype == BOOTP_ETHERNET) &&
            (bootp->hlen == 6) &&
            (bootp->magic == ntohl(BOOTP_DHCP_MAGIC_COOKIE))) {

            SCLogDebug("Parsing DHCP request len=%"PRIu32"state=%p", input_len, dhcp_state);
#ifdef PRINT
            PrintRawDataFp(stdout, input, input_len);
#endif

            DHCPOpt *dhcp = (DHCPOpt *)(input + sizeof(BOOTPHdr));

            if ((dhcp->code == DHCP_DHCP_MSG_TYPE) &&
                (dhcp->len == 1)) {
                DHCPTransaction *tx;

                switch (dhcp->args[0]) {
                    case DHCP_DISCOVER:
                    case DHCP_REQUEST:
                        tx = DHCPGetTxByXid(dhcp_state, bootp->xid);
                        if (unlikely(tx == NULL)) {
                            tx = DHCPTxAlloc(dhcp_state);
                            if (unlikely(tx == NULL)) {
                                SCLogDebug("Failed to allocate new DHCP tx.");
                                goto end;
                            }
                            tx->xid = bootp->xid;
                            SCLogDebug("Allocated DHCP tx %"PRIu64".", ntohl(tx->xid));
                            tx->request_buffer_len = input_len - sizeof(BOOTPHdr);
                            tx->request_buffer = SCMalloc(tx->request_buffer_len);
                            if (unlikely(tx->request_buffer == NULL)) {
                                /* TBD: need to remove from global tx list */
                                DHCPTxFree(dhcp_state, tx, 0);
                                goto end;
                            }
                            memcpy(tx->request_buffer, dhcp, tx->request_buffer_len);
                        }
                        break;
                    case DHCP_INFORM:
                        tx = DHCPGetTxByXid(dhcp_state, bootp->xid);
                        if (unlikely(tx == NULL)) {
                            tx = DHCPTxAlloc(dhcp_state);
                            if (unlikely(tx == NULL)) {
                                SCLogDebug("Failed to allocate new DHCP tx.");
                                goto end;
                            }
                            SCLogDebug("Allocated DHCP tx %"PRIu64".", ntohl(tx->tx_id));
                            tx->xid = bootp->xid;
                            tx->request_client_ip = bootp->ciaddr;
                            tx->request_buffer_len = input_len - sizeof(BOOTPHdr);
                            tx->request_buffer = SCMalloc(tx->request_buffer_len);
                            if (unlikely(tx->request_buffer == NULL)) {
                                /* TBD: need to remove from global tx list */
                                DHCPTxFree(dhcp_state, tx, 0);
                                goto end;
                            }
                            memcpy(tx->request_buffer, dhcp, tx->request_buffer_len);
                        }
                        break;
                    case DHCP_RELEASE:
                    case DHCP_DECLINE:
                        tx = DHCPGetTxByXid(dhcp_state, bootp->xid);
                        if (unlikely(tx == NULL)) {
                            tx = DHCPTxAlloc(dhcp_state);
                            if (unlikely(tx == NULL)) {
                                SCLogDebug("Failed to allocate new DHCP tx.");
                                goto end;
                            }
                            tx->xid = bootp->xid;
                            SCLogDebug("Allocated DHCP tx %"PRIu64".", ntohl(tx->xid));
                            tx->request_buffer_len = input_len - sizeof(BOOTPHdr);
                            tx->request_buffer = SCMalloc(tx->request_buffer_len);
                            if (unlikely(tx->request_buffer == NULL)) {
                                /* TBD: need to remove from global tx list */
                                DHCPTxFree(dhcp_state, tx, 0);
                                goto end;
                            }
                            memcpy(tx->request_buffer, dhcp, tx->request_buffer_len);
                            /* response to release not required */
                            tx->response_unneeded = 1;
                            tx->response_done = 1;
                        }
                        break;
                    default:
                        SCLogDebug("DHCP unknown %d", dhcp->args[0]);
                        break;
                }
            }
        } else if ((bootp->op == BOOTP_REPLY) &&
            (bootp->htype == BOOTP_ETHERNET) &&
            (bootp->hlen == 6) &&
            (bootp->magic == ntohl(BOOTP_DHCP_MAGIC_COOKIE))) {

            SCLogDebug("Parsing DHCP reply len=%"PRIu32"state=%p", input_len, dhcp_state);
#ifdef PRINT
            PrintRawDataFp(stdout, input, input_len);
#endif

            BOOTPHdr *bootp = (BOOTPHdr *)input;
            DHCPOpt *dhcp = (DHCPOpt *)(input + sizeof(BOOTPHdr));

            if ((dhcp->code == DHCP_DHCP_MSG_TYPE) &&
                (dhcp->len == 1)) {
                DHCPTransaction *tx;

                switch (dhcp->args[0]) {
                    case DHCP_OFFER:
                    case DHCP_ACK:
                        tx = DHCPGetTxByXid(dhcp_state, bootp->xid);
                        if (unlikely(tx == NULL)) {
                            goto end;
                        }
                        tx->response_client_ip = bootp->yiaddr;
                        if (tx->response_buffer == NULL) {
                            tx->response_buffer_len = input_len - sizeof(BOOTPHdr);
                            tx->response_buffer = SCMalloc(tx->response_buffer_len);
                            if (unlikely(tx->response_buffer == NULL)) {
                                /* TBD: need to remove from global tx list */
                                DHCPTxFree(dhcp_state, tx, 0);
                                goto end;
                            }
                            memcpy(tx->response_buffer, dhcp, tx->response_buffer_len);
                            tx->response_done = 1;
                        }
                        break;
                    case DHCP_NACK:
                        tx = DHCPGetTxByXid(dhcp_state, bootp->xid);
                        if (unlikely(tx == NULL)) {
                            goto end;
                        }
                        if (tx->response_buffer == NULL) {
                            tx->response_buffer_len = input_len - sizeof(BOOTPHdr);
                            tx->response_buffer = SCMalloc(tx->response_buffer_len);
                            if (unlikely(tx->response_buffer == NULL)) {
                                /* TBD: need to remove from global tx list */
                                DHCPTxFree(dhcp_state, tx, 0);
                                goto end;
                            }
                            memcpy(tx->response_buffer, dhcp, tx->response_buffer_len);
                            tx->response_done = 1;
                        }
                        break;
                    default:
                        SCLogDebug("DHCP unknown %d", dhcp->args[0]);
                        break;
                }
            }
        }

    }

end:    
    return 0;
}

static uint64_t DHCPGetTxCnt(void *state)
{
    DHCPState *dhcp = state;
    SCLogDebug("Current tx count is %"PRIu64".", dhcp->transaction_max);
    return dhcp->transaction_max;
}

static void *DHCPGetTx(void *state, uint64_t tx_id)
{
    DHCPState *dhcp = state;
    DHCPTransaction *tx;

    SCLogDebug("Requested tx ID %"PRIu64".", tx_id);

    SCMutexLock(&dhcp->lock);
    TAILQ_FOREACH(tx, &dhcp->tx_list, next) {
        if (tx->tx_id == tx_id) {
            SCMutexUnlock(&dhcp->lock);
            SCLogDebug("Transaction %"PRIu64" found, returning tx object %p.",
                tx_id, tx);
            return tx;
        }
    }
    SCMutexUnlock(&dhcp->lock);

    SCLogDebug("Transaction ID %"PRIu64" not found.", tx_id);
    return NULL;
}

/**
 * \brief Called by the application layer.
 *
 * In most cases 1 can be returned here.
 */
static int DHCPGetAlstateProgressCompletionStatus(uint8_t direction) {
    return 1;
}

/**
 * \brief Return the state of a transaction in a given direction.
 *
 * In the case of the echo protocol, the existence of a transaction
 * means that the request is done. However, some protocols that may
 * need multiple chunks of data to complete the request may need more
 * than just the existence of a transaction for the request to be
 * considered complete.
 *
 * For the response to be considered done, the response for a request
 * needs to be seen.  The response_done flag is set on response for
 * checking here.
 */
static int DHCPGetStateProgress(void *tx, uint8_t direction)
{
    DHCPTransaction *dhcptx = tx;

    SCLogDebug("Transaction progress requested for tx ID %"PRIu64
        ", direction=0x%02x", dhcptx->tx_id, direction);

    if (dhcptx->response_done) {
        return 1;
    }

    return 0;
}

/**
 * \brief ???
 */
static DetectEngineState *DHCPGetTxDetectState(void *vtx)
{
    DHCPTransaction *tx = vtx;
    return tx->de_state;
}

/**
 * \brief ???
 */
static int DHCPSetTxDetectState(void *state, void *vtx,
    DetectEngineState *s)
{
    DHCPTransaction *tx = vtx;
    tx->de_state = s;
    return 0;
}

void RegisterDHCPParsers(void)
{
    char *proto_name = "dhcp";

    if (AppLayerProtoDetectConfProtoDetectionEnabled("udp", proto_name)) {

        SCLogNotice("DHCP UDP protocol detection enabled.");

        AppLayerProtoDetectRegisterProtocol(ALPROTO_DHCP, proto_name);

        if (RunmodeIsUnittests()) {

            SCLogNotice("Unittest mode, registeringd default configuration.");
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, DHCP_DEFAULT_SERVER_PORT,
                ALPROTO_DHCP, 0, DHCP_MIN_FRAME_LEN, STREAM_TOSERVER,
                DHCPToServerProbingParser, NULL);

            AppLayerProtoDetectPPRegister(IPPROTO_TCP, DHCP_DEFAULT_CLIENT_PORT,
                ALPROTO_DHCP/*_CLIENT*/, 0, DHCP_MIN_FRAME_LEN, STREAM_TOSERVER,
                DHCPToClientProbingParser, NULL);

        }
        else {

            if (!AppLayerProtoDetectPPParseConfPorts("udp", IPPROTO_UDP,
                    proto_name, ALPROTO_DHCP, 0, DHCP_MIN_FRAME_LEN,
                    DHCPToServerProbingParser, NULL)) {
                SCLogNotice("No DHCP app-layer configuration, enabling DHCP"
                    " detection UDP detection on port %s.",
                    DHCP_DEFAULT_SERVER_PORT);
                AppLayerProtoDetectPPRegister(IPPROTO_UDP,
                    DHCP_DEFAULT_SERVER_PORT, ALPROTO_DHCP, 0,
                    DHCP_MIN_FRAME_LEN, STREAM_TOSERVER,
                    DHCPToServerProbingParser, NULL);
            }

            if (!AppLayerProtoDetectPPParseConfPorts("udp", IPPROTO_UDP,
                    proto_name, ALPROTO_DHCP/*_CLIENT*/, 0, DHCP_MIN_FRAME_LEN,
                    DHCPToClientProbingParser, NULL)) {
                SCLogNotice("No DHCP app-layer configuration, enabling DHCP"
                    " detection UDP detection on port %s.",
                    DHCP_DEFAULT_CLIENT_PORT);
                AppLayerProtoDetectPPRegister(IPPROTO_UDP,
                    DHCP_DEFAULT_CLIENT_PORT, ALPROTO_DHCP/*_CLIENT*/, 0,
                    DHCP_MIN_FRAME_LEN, STREAM_TOSERVER,
                    DHCPToClientProbingParser, NULL);
            }


        }

    }

    else {
        SCLogNotice("Protocol detecter and parser disabled for DHCP.");
        return;
    }

    if (AppLayerParserConfParserEnabled("udp", proto_name)) {

        SCLogNotice("Registering DHCP protocol parser.");

        /* Register functions for state allocation and freeing. A
         * state is allocated for every new DHCP flow. */
        AppLayerParserRegisterStateFuncs(IPPROTO_UDP, ALPROTO_DHCP,
            DHCPStateAlloc, DHCPStateFree);

        /* Register request parser for parsing frame from server to client. */
        AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_DHCP,
            STREAM_TOSERVER, DHCPParse);

        /* Register response parser for parsing frames from server to client. */
        AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_DHCP,
            STREAM_TOCLIENT, DHCPParse);

        /* Register a function to be called by the application layer
         * when a transaction is to be freed. */
        AppLayerParserRegisterTxFreeFunc(IPPROTO_UDP, ALPROTO_DHCP,
            DHCPStateTxFree);

        /* Register a function to return the current transaction count. */
        AppLayerParserRegisterGetTxCnt(IPPROTO_UDP, ALPROTO_DHCP,
            DHCPGetTxCnt);

        /* Transaction handling. */
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_DHCP,
            DHCPGetAlstateProgressCompletionStatus);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_UDP,
            ALPROTO_DHCP, DHCPGetStateProgress);
        AppLayerParserRegisterGetTx(IPPROTO_UDP, ALPROTO_DHCP,
            DHCPGetTx);

        /* Application layer event handling. */
        AppLayerParserRegisterHasEventsFunc(IPPROTO_UDP, ALPROTO_DHCP,
            DHCPHasEvents);

        /* What is this being registered for? */
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_UDP, ALPROTO_DHCP,
            NULL, DHCPGetTxDetectState, DHCPSetTxDetectState);

        AppLayerParserRegisterGetEventInfo(IPPROTO_UDP, ALPROTO_DHCP,
            DHCPStateGetEventInfo);
        AppLayerParserRegisterGetEventsFunc(IPPROTO_UDP, ALPROTO_DHCP,
            DHCPGetEvents);
    }
    else {
        SCLogNotice("DHCP protocol parsing disabled.");
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_UDP, ALPROTO_DHCP,
        DHCPParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void DHCPParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}

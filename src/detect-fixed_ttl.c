/* Copyright (C) 2015-2017 Open Information Security Foundation
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
 * \file
 *
 * \author XXX Yourname <youremail@yourdomain>
 *
 * XXX Short description of the purpose of this keyword
 */

#include "suricata-common.h"
#include "util-unittest.h"

#include "detect-parse.h"
#include "detect-engine.h"

#include "detect-fixed_ttl.h"

#include "host-storage.h"

/**
 * \brief Regex for parsing our keyword options
 */
#define PARSE_REGEX  "^\\s*([0-9]+)?\\s*,s*([0-9]+)?\\s*$"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

/* Prototypes of functions registered in DetectFixed_ttlRegister below */
static int DetectFixed_ttlMatch (ThreadVars *, DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectFixed_ttlSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectFixed_ttlFree (void *);
static void DetectFixed_ttlRegisterTests (void);

static int storage_id = -1;

static void TtlStorageFree(void *ptr)
{
    if (ptr != NULL) {
        SCFree(ptr);
    }
}

/**
 * \brief Registration function for fixed_ttl: keyword
 *
 * This function is called once in the 'lifetime' of the engine.
 */
void DetectFixed_ttlRegister(void) {
    /* keyword name: this is how the keyword is used in a rule */
    sigmatch_table[DETECT_FIXED_TTL].name = "fixed_ttl";
    /* description: listed in "suricata --list-keywords=all" */
    sigmatch_table[DETECT_FIXED_TTL].desc = "give an introduction into how a detection module works";
    /* link to further documentation of the keyword. Normally on the Suricata redmine/wiki */
    sigmatch_table[DETECT_FIXED_TTL].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Developers_Guide";
    /* match function is called when the signature is inspected on a packet */
    sigmatch_table[DETECT_FIXED_TTL].Match = DetectFixed_ttlMatch;
    /* setup function is called during signature parsing, when the fixed_ttl
     * keyword is encountered in the rule */
    sigmatch_table[DETECT_FIXED_TTL].Setup = DetectFixed_ttlSetup;
    /* free function is called when the detect engine is freed. Normally at
     * shutdown, but also during rule reloads. */
    sigmatch_table[DETECT_FIXED_TTL].Free = DetectFixed_ttlFree;
    /* registers unittests into the system */
    sigmatch_table[DETECT_FIXED_TTL].RegisterTests = DetectFixed_ttlRegisterTests;
    sigmatch_table[DETECT_FIXED_TTL].flags |= SIGMATCH_NOOPT;

    /* set up the PCRE for keyword parsing */
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);

    storage_id = HostStorageRegister("detect-fixed-ttl",
            sizeof(void *), NULL, TtlStorageFree);
    SCLogNotice("Allocated storage ID %d", storage_id);
}

/**
 * \brief This function is used to match FIXED_TTL rule option on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch with context that we will cast into DetectFixed_ttlData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectFixed_ttlMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p,
                                const Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;

    if (PKT_IS_PSEUDOPKT(p)) {
        return 0;
    }

    if (!PKT_IS_IPV4(p)) {
        return 0;
    }

    if (p->host_src == NULL) {
        p->host_src = HostGetHostFromHash(&p->src);
        if (p->host_src == NULL) {
            SCLogNotice("Failed to get host from hash.");
            return 0;
        }
    }
    
    uint8_t ttl = IPV4_GET_RAW_IPTTL(p->ip4h);
    
    void *store = HostGetStorageById(p->host_src, storage_id);
    if (store == NULL) {
        uint8_t *ttlp = SCMalloc(sizeof(uint8_t));
        *ttlp = ttl;
        HostSetStorageById(p->host_src, storage_id, ttlp);
    } else {
        uint8_t pttl = *(uint8_t *)store;
        if (pttl != ttl) {
            *(uint8_t *)store = ttl;
            HostSetStorageById(p->host_src, storage_id, store);
            ret = 1;
        }
    }
    
    HostUnlock(p->host_src);
    
    return ret;
}

/**
 * \brief parse the options from the 'fixed_ttl' keyword in the rule into
 *        the Signature data structure.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param fixed_ttlstr pointer to the user provided fixed_ttl options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFixed_ttlSetup (DetectEngineCtx *de_ctx, Signature *s, const char *fixed_ttlstr)
{
    SigMatch *sm = NULL;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FIXED_TTL;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectFixed_ttlData
 *
 * \param ptr pointer to DetectFixed_ttlData
 */
static void DetectFixed_ttlFree(void *ptr) {
    DetectFixed_ttlData *fixed_ttld = (DetectFixed_ttlData *)ptr;

    /* do more specific cleanup here, if needed */

    SCFree(fixed_ttld);
}

#ifdef UNITTESTS

/**
 * \test description of the test
 */

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectFixed_ttl
 */
void DetectFixed_ttlRegisterTests(void) {
#ifdef UNITTESTS
#endif /* UNITTESTS */
}

/* Copyright (C) 2015-2016 Open Information Security Foundation
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

#include "detect-spi.h"

/**
 * \brief Regex for parsing our keyword options
 */
#define PARSE_REGEX  "^\\s*([0-9]+)?\\s*,s*([0-9]+)?\\s*$"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

/* Prototypes of functions registered in DetectSpiRegister below */
static int DetectSpiMatch (ThreadVars *, DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectSpiSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectSpiFree (void *);
static void DetectSpiRegisterTests (void);

/**
 * \brief Registration function for spi: keyword
 *
 * This function is called once in the 'lifetime' of the engine.
 */
void DetectSpiRegister(void) {
    /* keyword name: this is how the keyword is used in a rule */
    sigmatch_table[DETECT_SPI].name = "spi";
    /* description: listed in "suricata --list-keywords=all" */
    sigmatch_table[DETECT_SPI].desc = "give an introduction into how a detection module works";
    /* link to further documentation of the keyword. Normally on the Suricata redmine/wiki */
    sigmatch_table[DETECT_SPI].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Developers_Guide";
    /* match function is called when the signature is inspected on a packet */
    sigmatch_table[DETECT_SPI].Match = DetectSpiMatch;
    /* setup function is called during signature parsing, when the spi
     * keyword is encountered in the rule */
    sigmatch_table[DETECT_SPI].Setup = DetectSpiSetup;
    /* free function is called when the detect engine is freed. Normally at
     * shutdown, but also during rule reloads. */
    sigmatch_table[DETECT_SPI].Free = DetectSpiFree;
    /* registers unittests into the system */
    sigmatch_table[DETECT_SPI].RegisterTests = DetectSpiRegisterTests;

    /* set up the PCRE for keyword parsing */
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);
}

/**
 * \brief This function is used to match SPI rule option on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch with context that we will cast into DetectSpiData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectSpiMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p,
                                const Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;
    const DetectSpiData *spid = (const DetectSpiData *) ctx;
    if (PKT_IS_PSEUDOPKT(p)) {
        /* fake pkt */
        return 0;
    }

    if (p->esph == NULL) {
        return 0;
    }

    if (PKT_IS_IPV4(p)) {
        /* ipv4 pkt */
        uint32_t spi = ntohl(p->esph->spi);
        if (spi == spid->spi) {
            ret = 1;
        }
    } else {
        SCLogDebug("packet is of not IPv4 or IPv6");
    }
    return ret;
}

/**
 * \brief This function is used to parse spi options passed via spi: keyword
 *
 * \param spistr Pointer to the user provided spi options
 *
 * \retval spid pointer to DetectSpiData on success
 * \retval NULL on failure
 */
static DetectSpiData *DetectSpiParse (const char *spistr)
{
    DetectSpiData *spid = NULL;

    spid = SCMalloc(sizeof (DetectSpiData));
    if (unlikely(spid == NULL))
        goto error;
    spid->spi = (uint32_t)atoi(spistr);

    return spid;

error:
    if (spid)
        SCFree(spid);
    return NULL;
}

/**
 * \brief parse the options from the 'spi' keyword in the rule into
 *        the Signature data structure.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param spistr pointer to the user provided spi options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectSpiSetup (DetectEngineCtx *de_ctx, Signature *s, const char *spistr)
{
    DetectSpiData *spid = NULL;
    SigMatch *sm = NULL;

    spid = DetectSpiParse(spistr);
    if (spid == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_SPI;
    sm->ctx = (void *)spid;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (spid != NULL)
        DetectSpiFree(spid);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectSpiData
 *
 * \param ptr pointer to DetectSpiData
 */
static void DetectSpiFree(void *ptr) {
    DetectSpiData *spid = (DetectSpiData *)ptr;

    /* do more specific cleanup here, if needed */

    SCFree(spid);
}

#ifdef UNITTESTS

/**
 * \test description of the test
 */

static int DetectSpiParseTest01 (void)
{
    DetectSpiData *spid = DetectSpiParse("123");
    FAIL_IF_NULL(spid);
    FAIL_IF(!(spid->spi == 123));
    DetectSpiFree(spid);
    PASS;
}

static int DetectSpiSignatureTest01 (void)
{
#if 0
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (spi:1,10; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);
#endif
    PASS;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectSpi
 */
void DetectSpiRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DetectSpiParseTest01", DetectSpiParseTest01);
    UtRegisterTest("DetectSpiSignatureTest01",
                   DetectSpiSignatureTest01);
#endif /* UNITTESTS */
}

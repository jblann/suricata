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

#include "detect-udplite_coverage.h"

/**
 * \brief Regex for parsing our keyword options
 */
#define PARSE_REGEX  "^\\s*([0-9]+)?\\s*,s*([0-9]+)?\\s*$"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

/* Prototypes of functions registered in DetectUdplite_coverageRegister below */
static int DetectUdplite_coverageMatch (ThreadVars *, DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectUdplite_coverageSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectUdplite_coverageFree (void *);
static void DetectUdplite_coverageRegisterTests (void);

/**
 * \brief Registration function for udplite_coverage: keyword
 *
 * This function is called once in the 'lifetime' of the engine.
 */
void DetectUdpliteCoverageRegister(void) {
    /* keyword name: this is how the keyword is used in a rule */
    sigmatch_table[DETECT_UDPLITE_COVERAGE].name = "udplite_coverage";
    /* description: listed in "suricata --list-keywords=all" */
    sigmatch_table[DETECT_UDPLITE_COVERAGE].desc = "give an introduction into how a detection module works";
    /* link to further documentation of the keyword. Normally on the Suricata redmine/wiki */
    sigmatch_table[DETECT_UDPLITE_COVERAGE].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Developers_Guide";
    /* match function is called when the signature is inspected on a packet */
    sigmatch_table[DETECT_UDPLITE_COVERAGE].Match = DetectUdplite_coverageMatch;
    /* setup function is called during signature parsing, when the udplite_coverage
     * keyword is encountered in the rule */
    sigmatch_table[DETECT_UDPLITE_COVERAGE].Setup = DetectUdplite_coverageSetup;
    /* free function is called when the detect engine is freed. Normally at
     * shutdown, but also during rule reloads. */
    sigmatch_table[DETECT_UDPLITE_COVERAGE].Free = DetectUdplite_coverageFree;
    /* registers unittests into the system */
    sigmatch_table[DETECT_UDPLITE_COVERAGE].RegisterTests = DetectUdplite_coverageRegisterTests;

    /* set up the PCRE for keyword parsing */
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);
}

/**
 * \brief This function is used to match UDPLITE_COVERAGE rule option on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch with context that we will cast into DetectUdplite_coverageData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectUdplite_coverageMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p,
                                const Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;
    const DetectUdpliteCoverageData *udplite_coveraged =
        (const DetectUdpliteCoverageData *) ctx;

    if (PKT_IS_PSEUDOPKT(p)) {
        return 0;
    }

    if (PKT_IS_IPV4(p)) {
        uint16_t coverage = ntohs(p->udpliteh->coverage);
        if (coverage == udplite_coveraged->coverage) {
            ret = 1;
        }
    } else if (PKT_IS_IPV6(p)) {
        /* IPv6 not yet supported. */
    } else {
        SCLogDebug("packet is of not IPv4 or IPv6");
        return ret;
    }

    return ret;
}

/**
 * \brief This function is used to parse udplite_coverage options passed via udplite_coverage: keyword
 *
 * \param udplite_coveragestr Pointer to the user provided udplite_coverage options
 *
 * \retval udplite_coveraged pointer to DetectUdplite_coverageData on success
 * \retval NULL on failure
 */
static DetectUdpliteCoverageData *DetectUdplite_coverageParse (const char *coveragestr)
{
    DetectUdpliteCoverageData *coveraged = NULL;

    coveraged = SCMalloc(sizeof (*coveraged));
    if (unlikely(coveraged == NULL))
        goto error;
    coveraged->coverage = (uint32_t)atoi(coveragestr);

    return coveraged;

error:
    if (coveraged)
        SCFree(coveraged);
    return NULL;
}

/**
 * \brief parse the options from the 'udplite_coverage' keyword in the rule into
 *        the Signature data structure.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param udplite_coveragestr pointer to the user provided udplite_coverage options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectUdplite_coverageSetup (DetectEngineCtx *de_ctx, Signature *s, const char *udplite_coveragestr)
{
    DetectUdpliteCoverageData *udplite_coveraged = NULL;
    SigMatch *sm = NULL;

    udplite_coveraged = DetectUdplite_coverageParse(udplite_coveragestr);
    if (udplite_coveraged == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_UDPLITE_COVERAGE;
    sm->ctx = (void *)udplite_coveraged;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (udplite_coveraged != NULL)
        DetectUdplite_coverageFree(udplite_coveraged);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectUdplite_coverageData
 *
 * \param ptr pointer to DetectUdplite_coverageData
 */
static void DetectUdplite_coverageFree(void *ptr) {
    DetectUdpliteCoverageData *udplite_coveraged = (DetectUdpliteCoverageData *)ptr;

    /* do more specific cleanup here, if needed */

    SCFree(udplite_coveraged);
}

#ifdef UNITTESTS

/**
 * \test description of the test
 */

static int DetectUdplite_coverageParseTest01 (void)
{
     DetectUdpliteCoverageData *cd = DetectUdplite_coverageParse("1280");
    FAIL_IF_NULL(cd);
    FAIL_IF(!(cd->coverage == 1280));
    DetectUdplite_coverageFree(cd);
    PASS;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectUdplite_coverage
 */
void DetectUdplite_coverageRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DetectUdplite_coverageParseTest01", DetectUdplite_coverageParseTest01);
#endif /* UNITTESTS */
}

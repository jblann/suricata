/* Copyright (C) 2007-2010 Open Information Security Foundation
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

#include "suricata-common.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-erf-dag.h"
#include "output.h"

#include "detect-engine.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-runmodes.h"

#include "source-erf-dag.h"

static const char *default_mode;

static int DagConfigGetThreadCount(void *conf)
{
    return 1;
}

static void *ParseDagConfig(const char *iface)
{
    ConfNode *if_root;
    ConfNode *if_default = NULL;
    ConfNode *dag_packet_node;
    DagIfaceConfig *dconf = SCMalloc(sizeof(*dconf));
    char *copymodestr;

    if (unlikely(dconf == NULL)) {
        return NULL;
    }

    if (iface == NULL) {
        SCFree(dconf);
        return NULL;
    }

    strlcpy(dconf->iface, iface, sizeof(dconf->iface));

    dconf->copy_mode = DAG_COPY_MODE_NONE;

    /* Find initial node */
    dag_packet_node = ConfGetNode("dag-packet");
    if (dag_packet_node == NULL) {
        SCLogInfo("Unable to find dag-packet config using default value");
        return dconf;
    }

    if_root = ConfNodeLookupKeyValue(dag_packet_node, "interface", iface);

    if_default = ConfNodeLookupKeyValue(dag_packet_node, "interface", "default");

    if (ConfGetChildValueWithDefault(if_root, if_default, "copy-mode", &copymodestr) == 1) {
        if (strcmp(copymodestr, "ips") == 0) {
            SCLogInfo("ERF-DAG IPS mode activated %s",
                    iface);
            dconf->copy_mode = DAG_COPY_MODE_IPS;
        } else if (strcmp(copymodestr, "tap") == 0) {
            SCLogInfo("ERF-DAG TAP mode activated %s",
                    iface);
            dconf->copy_mode = DAG_COPY_MODE_TAP;
        } else {
            SCLogInfo("Invalid mode (not in tap, ips)");
        }
    }

    return dconf;
}

const char *RunModeErfDagGetDefaultMode(void)
{
    return default_mode;
}

void RunModeErfDagRegister(void)
{
    default_mode = "workers";

    RunModeRegisterNewRunMode(RUNMODE_DAG, "autofp",
        "Multi threaded DAG mode.  Packets from "
        "each flow are assigned to a single detect "
        "thread, unlike \"dag_auto\" where packets "
        "from the same flow can be processed by any "
        "detect thread",
        RunModeIdsErfDagAutoFp);

    RunModeRegisterNewRunMode(RUNMODE_DAG, "single",
        "Singled threaded DAG mode",
        RunModeIdsErfDagSingle);

    RunModeRegisterNewRunMode(RUNMODE_DAG, "workers",
        "Workers DAG mode, each thread does all "
        " tasks from acquisition to logging",
        RunModeIdsErfDagWorkers);

    return;
}

int RunModeIdsErfDagSingle(void)
{
    int ret;

    SCEnter();

    RunModeInitialize();

    TimeModeSetLive();

    ret = RunModeSetLiveCaptureSingle(ParseDagConfig,
        DagConfigGetThreadCount,
        "ReceiveErfDag",
        "DecodeErfDag",
        "RxDAG",
        NULL);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "DAG single runmode failed to start");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIdsDagSingle initialised");

    SCReturnInt(0);
}

int RunModeIdsErfDagAutoFp(void)
{
    int ret;

    SCEnter();

    RunModeInitialize();

    TimeModeSetLive();

    ret = RunModeSetLiveCaptureAutoFp(ParseDagConfig,
        DagConfigGetThreadCount,
        "ReceiveErfDag",
        "DecodeErfDag",
        "RxDAG",
        NULL);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "DAG autofp runmode failed to start");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIdsDagAutoFp initialised");

    SCReturnInt(0);
}

int RunModeIdsErfDagWorkers(void)
{
    int ret;

    SCEnter();

    RunModeInitialize();

    TimeModeSetLive();

    ret = RunModeSetLiveCaptureWorkers(ParseDagConfig,
        DagConfigGetThreadCount,
        "ReceiveErfDag",
        "DecodeErfDag",
        "RxDAG",
        NULL);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "DAG workers runmode failed to start");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIdsErfDagWorkers initialised");

    SCReturnInt(0);
}

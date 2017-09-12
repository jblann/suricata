/* Copyright (C) 2017 Open Information Security Foundation
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
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "conf.h"

#include "threads.h"
#include "tm-threads.h"
#include "threadvars.h"
#include "util-debug.h"

#include "output.h"
#include "output-json.h"
#include "output-json-udplite.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-print.h"
#include "util-logopenfile.h"
#include "util-time.h"
#include "util-buffer.h"

#define MODULE_NAME "JsonTemplatePacketLog"

#ifdef HAVE_LIBJANSSON

typedef struct JsonTemplatePacketOutputCtx_ {
    LogFileCtx *file_ctx;
    uint8_t flags;
} JsonTemplatePacketOutputCtx;

typedef struct JsonTemplatePacketLogThread_ {
    JsonTemplatePacketOutputCtx *template_ctx;
    MemBuffer *buffer;
} JsonTemplatePacketLogThread;

#define OUTPUT_BUFFER_SIZE 65535

static TmEcode JsonTemplatePacketLogThreadInit(ThreadVars *t,
        const void *initdata, void **data)
{
    JsonTemplatePacketLogThread *aft = SCMalloc(sizeof(JsonTemplatePacketLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(*aft));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogTemplatePacket.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /** Use the Ouptut Context (file pointer and mutex) */
    aft->template_ctx = ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode JsonTemplatePacketLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonTemplatePacketLogThread *aft = (JsonTemplatePacketLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);

    /* clear memory */
    memset(aft, 0, sizeof(*aft));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void JsonTemplatePacketOutputCtxFree(JsonTemplatePacketOutputCtx *template_ctx)
{
    if (template_ctx != NULL) {
        if (template_ctx->file_ctx != NULL)
            LogFileFreeCtx(template_ctx->file_ctx);
        SCFree(template_ctx);
    }
}

static void JsonTemplatePacketLogDeInitCtx(OutputCtx *output_ctx)
{
    JsonTemplatePacketOutputCtx *template_ctx = output_ctx->data;
    JsonTemplatePacketOutputCtxFree(template_ctx);
    SCFree(output_ctx);
}

static void JsonTemplatePacketLogDeInitCtxSub(OutputCtx *output_ctx)
{
    JsonTemplatePacketOutputCtx *template_ctx = output_ctx->data;
    SCFree(template_ctx);
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    SCFree(output_ctx);
}

#define DEFAULT_LOG_FILENAME "template-packet.json"

static OutputCtx *JsonTemplatePacketLogInitCtx(ConfNode *conf)
{
    JsonTemplatePacketOutputCtx *template_ctx = SCCalloc(1, sizeof(*template_ctx));
    if (template_ctx == NULL)
        return NULL;

    template_ctx->file_ctx = LogFileNewCtx();
    if (template_ctx->file_ctx == NULL) {
        JsonTemplatePacketOutputCtxFree(template_ctx);
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, template_ctx->file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        JsonTemplatePacketOutputCtxFree(template_ctx);
        return NULL;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        JsonTemplatePacketOutputCtxFree(template_ctx);
        return NULL;
    }

    output_ctx->data = template_ctx;
    output_ctx->DeInit = JsonTemplatePacketLogDeInitCtx;
    return output_ctx;
}

static OutputCtx *JsonTemplatePacketLogInitCtxSub(ConfNode *conf,
        OutputCtx *parent_ctx)
{
    AlertJsonThread *ajt = parent_ctx->data;

    JsonTemplatePacketOutputCtx *template_ctx = SCCalloc(1, sizeof(*template_ctx));
    if (template_ctx == NULL)
        return NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        JsonTemplatePacketOutputCtxFree(template_ctx);
        return NULL;
    }

    template_ctx->file_ctx = ajt->file_ctx;

    output_ctx->data = template_ctx;
    output_ctx->DeInit = JsonTemplatePacketLogDeInitCtxSub;
    return output_ctx;
}

/**
 * \brief The log function that is called for each that passed the
 *     condition.
 *
 * \param tv    Pointer the current thread variables
 * \param data  Pointer to the droplog struct
 * \param p     Pointer the packet which is being logged
 *
 * \retval 0 on succes
 */
static int JsonTemplatePacketLogger(ThreadVars *tv, void *thread_data,
        const Packet *p)
{
    JsonTemplatePacketLogThread *td = thread_data;

    /* Creates a JSON root object with an event-type of
     * "template-packet". */
    json_t *js = CreateJSONHeader((Packet *)p, 0, "udplite");
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    json_t *tjs = json_object();
    if (unlikely(tjs == NULL)) {
        json_decref(js);
        return TM_ECODE_OK;
    }

    /* Reset the re-used buffer. */
    MemBufferReset(td->buffer);

    /* Add the coverage value to the udplite object. */
    json_object_set_new(tjs, "coverage", json_integer(ntohs(p->udpliteh->coverage)));
    
    /* Add the tjs object to the root object. */
    json_object_set_new(js, "udplite", tjs);

    /* Output the buffer to the log destination. */
    OutputJSONBuffer(js, td->template_ctx->file_ctx, &td->buffer);

    /* Free the json object. */
    json_decref(js);

    return TM_ECODE_OK;
}


/**
 * \brief Check if this packet should be logged or not.
 *
 * \retval bool TRUE or FALSE
 */
static int JsonTemplatePacketLogCondition(ThreadVars *tv, const Packet *p)
{
    /* Only log if we have a UDPLite header. */
    if (p->udpliteh != NULL) {
        return TRUE;
    }
    return FALSE;
}

void JsonTemplatePacketLogRegister(void)
{
    OutputRegisterPacketModule(LOGGER_JSON_DROP, MODULE_NAME,
        "json-udplite-log", JsonTemplatePacketLogInitCtx,
        JsonTemplatePacketLogger, JsonTemplatePacketLogCondition,
        JsonTemplatePacketLogThreadInit, JsonTemplatePacketLogThreadDeinit,
        NULL);
    OutputRegisterPacketSubModule(LOGGER_JSON_DROP, "eve-log", MODULE_NAME,
        "eve-log.udplite", JsonTemplatePacketLogInitCtxSub,
        JsonTemplatePacketLogger, JsonTemplatePacketLogCondition,
        JsonTemplatePacketLogThreadInit, JsonTemplatePacketLogThreadDeinit,
        NULL);
}

#else

void JsonTemplatePacketLogRegister(void)
{
}

#endif

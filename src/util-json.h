#include <stdbool.h>

#pragma once

typedef struct SCJson_ SCJson;

SCJson *SCJsonNew(void);
SCJson *SCJsonCopy(SCJson *js);
SCJson *SCJsonWrap(char *buf, size_t size);
void SCJsonReset(SCJson *js);
void SCJsonFree(SCJson *js);
bool SCJsonOpenObject(SCJson *js);
bool SCJsonCloseObject(SCJson *js);
bool SCJsonSetString(SCJson *js, const char *key, const char *val);
bool SCJsonSetInt(SCJson *js, const char *key, const intmax_t val);
bool SCJsonSetBool(SCJson *js, const char *key, const bool val);
bool SCJsonSetObject(SCJson *js, const char *key);
bool SCJsonSetList(SCJson *js, const char *key);
bool SCJsonAppendString(SCJson *js, const char *val);
bool SCJsonAppendInt(SCJson *js, const intmax_t val);
bool SCJsonCloseList(SCJson *js);

void SCJsonMark(SCJson *js);
void SCJsonRewind(SCJson *js);

const char *SCJsonGetBuf(SCJson *js);

void UtilJsonRegisterTests(void);

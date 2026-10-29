#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../cJSON.h"
#include "../../cJSON_Utils.h"

/* Input = JSON document A, optionally followed by a NUL and a second document B.
 * Exercises the cJSON_Utils patch / merge-patch / pointer / sort APIs. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *buf;
    size_t split;
    cJSON *a, *b = NULL, *work, *patches, *merge;
    char *ptr;

    if (size == 0) return 0;
    buf = (char *)malloc(size + 1);
    if (buf == NULL) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    split = strlen(buf);
    a = cJSON_Parse(buf);
    if (split < size) b = cJSON_Parse(buf + split + 1);

    if (a != NULL)
    {
        work = cJSON_Duplicate(a, 1);
        if (work != NULL)
        {
            cJSONUtils_SortObject(work);
            cJSON_Delete(work);
        }
        work = cJSON_Duplicate(a, 1);
        if (work != NULL)
        {
            cJSONUtils_SortObjectCaseSensitive(work);
            cJSON_Delete(work);
        }
        if (a->child != NULL)
        {
            ptr = cJSONUtils_FindPointerFromObjectTo(a, a->child);
            if (ptr != NULL) free(ptr);
        }
        if (split < size)
        {
            (void)cJSONUtils_GetPointer(a, buf + split + 1);
            (void)cJSONUtils_GetPointerCaseSensitive(a, buf + split + 1);
        }
    }

    if (a != NULL && b != NULL)
    {
        patches = cJSONUtils_GeneratePatches(a, b);
        if (patches != NULL)
        {
            work = cJSON_Duplicate(a, 1);
            if (work != NULL)
            {
                (void)cJSONUtils_ApplyPatches(work, patches);
                cJSON_Delete(work);
            }
            cJSON_Delete(patches);
        }

        patches = cJSONUtils_GeneratePatchesCaseSensitive(a, b);
        if (patches != NULL)
        {
            work = cJSON_Duplicate(a, 1);
            if (work != NULL)
            {
                (void)cJSONUtils_ApplyPatchesCaseSensitive(work, patches);
                cJSON_Delete(work);
            }
            cJSON_Delete(patches);
        }

        merge = cJSONUtils_GenerateMergePatch(a, b);
        if (merge != NULL)
        {
            work = cJSON_Duplicate(a, 1);
            if (work != NULL)
            {
                work = cJSONUtils_MergePatch(work, merge);
                cJSON_Delete(work);
            }
            cJSON_Delete(merge);
        }

        work = cJSON_Duplicate(a, 1);
        if (work != NULL)
        {
            work = cJSONUtils_MergePatchCaseSensitive(work, b);
            cJSON_Delete(work);
        }

        /* B interpreted directly as a patch array against A */
        work = cJSON_Duplicate(a, 1);
        if (work != NULL)
        {
            (void)cJSONUtils_ApplyPatches(work, b);
            cJSON_Delete(work);
        }
    }

    cJSON_Delete(a);
    cJSON_Delete(b);
    free(buf);
    return 0;
}

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../cJSON.h"
#include "../../cJSON_Utils.h"

/* Input = JSON document A, optionally followed by a NUL and a second document B.
 * Exercises the cJSON_Utils patch / merge-patch / pointer / sort APIs. */
/* The idx-th descendant of root in preorder (root itself excluded), or NULL. */
static cJSON *nth_descendant(cJSON *root, size_t *idx)
{
    cJSON *child, *found;
    for (child = root->child; child != NULL; child = child->next)
    {
        if (*idx == 0) return child;
        (*idx)--;
        found = nth_descendant(child, idx);
        if (found != NULL) return found;
    }
    return NULL;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *buf;
    size_t split;
    cJSON *a, *b = NULL, *work, *patches, *merge, *sub;
    size_t pick;
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
        /* Merge-patch a copy of A with one of its own non-object descendants as the patch.
         * The byte after the NUL (0 when absent) picks which node, in preorder. */
        pick = (split + 1 < size) ? (unsigned char)buf[split + 1] : 0;
        work = cJSON_Duplicate(a, 1);
        if (work != NULL)
        {
            sub = nth_descendant(work, &pick);
            if (sub != NULL && !cJSON_IsObject(sub))
            {
                work = cJSONUtils_MergePatch(work, sub);
            }
            cJSON_Delete(work);
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

/*
 * Host test for the LKM selection rules in app/src/main/jni/ko_select.h.
 *
 *   cc -std=gnu11 -Wall -Wextra -Werror -I app/src/main/jni \
 *      tests/ko_select_test.c -o /tmp/ko_select_test && /tmp/ko_select_test
 *
 * CI runs exactly that as the "Native selection logic tests" job. exp.c itself
 * cannot be compiled on a host - bionic-only, all page-cache patching and
 * .incbin blobs - which is why the rules live in a header this file includes.
 * The blob symbols below are stubs; only which table entry gets picked matters.
 */
#include <stdio.h>
#include <string.h>

#include "ko_select.h"

char dfroot_ko_12_5_10_start[8],  dfroot_ko_12_5_10_end[8];
char dfroot_ko_13_5_10_start[8],  dfroot_ko_13_5_10_end[8];
char dfroot_ko_13_5_15_start[8],  dfroot_ko_13_5_15_end[8];
char dfroot_ko_14_5_15_start[8],  dfroot_ko_14_5_15_end[8];
char dfroot_ko_14_6_1_start[8],   dfroot_ko_14_6_1_end[8];
char dfroot_ko_15_6_6_start[8],   dfroot_ko_15_6_6_end[8];
char dfroot_ko_16_6_12_start[8],  dfroot_ko_16_6_12_end[8];
char dfroot_ko_17_6_18_start[8],  dfroot_ko_17_6_18_end[8];

static int fails;

/* want == NULL means "whatever gets picked, only the counts matter here". */
static void check(int kmi, int major, int minor, const char *want,
                  int want_candidates, int want_exact, const char *why)
{
    int candidates = -1, exact = -1;
    const struct KoImage *ko = select_ko_image(kmi, major, minor, &candidates, &exact);
    char got[32];
    int ok;

    if (ko) snprintf(got, sizeof(got), "android%d-%d.%d",
                     ko->kmi, ko->kver_major, ko->kver_minor);
    else    snprintf(got, sizeof(got), "(none)");

    ok = (!want || (ko && strcmp(got, want) == 0));
    if (want && !ko) ok = 0;
    if (want_candidates >= 0 && candidates != want_candidates) ok = 0;
    if (want_exact >= 0 && exact != want_exact) ok = 0;

    printf("%-4s kernel %d.%d android%-3d -> %-16s candidates %d exact %d  %s\n",
           ok ? "ok" : "FAIL", major, minor, kmi, got, candidates, exact, why);
    if (!ok) fails++;
}

int main(void)
{
    static const int rows[][3] = {
        {12, 5, 10}, {13, 5, 10}, {13, 5, 15}, {14, 5, 15},
        {14, 6,  1}, {15, 6,  6}, {16, 6, 12}, {17, 6, 18},
    };
    const size_t nrows = sizeof(rows) / sizeof(rows[0]);
    char want[32];

    /* One row per committed .ko - keep in step with KO_FILES in CMakeLists.txt. */
    if (DFROOT_KO_IMAGE_COUNT != (int)nrows) {
        printf("FAIL table holds %d modules, test lists %zu\n",
               DFROOT_KO_IMAGE_COUNT, nrows);
        fails++;
    }

    /* No two rows may describe the same kernel, or the pair filter is ambiguous. */
    for (int i = 0; i < DFROOT_KO_IMAGE_COUNT; i++) {
        for (int j = i + 1; j < DFROOT_KO_IMAGE_COUNT; j++) {
            if (dfroot_ko_images[i].kmi == dfroot_ko_images[j].kmi &&
                dfroot_ko_images[i].kver_major == dfroot_ko_images[j].kver_major &&
                dfroot_ko_images[i].kver_minor == dfroot_ko_images[j].kver_minor) {
                printf("FAIL rows %d and %d are the same android%d-%d.%d\n", i, j,
                       dfroot_ko_images[i].kmi, dfroot_ko_images[i].kver_major,
                       dfroot_ko_images[i].kver_minor);
                fails++;
            }
        }
    }

    /* Every shipped module has to be reachable through its own KMI, and the
     * candidate count has to describe the whole kernel line rather than stop at
     * the hit: 5.10 and 5.15 each carry two levels, the rest carry one. */
    for (size_t i = 0; i < nrows; i++) {
        int pair = 0;
        for (size_t k = 0; k < nrows; k++)
            if (rows[k][1] == rows[i][1] && rows[k][2] == rows[i][2]) pair++;

        snprintf(want, sizeof(want), "android%d-%d.%d",
                 rows[i][0], rows[i][1], rows[i][2]);
        check(rows[i][0], rows[i][1], rows[i][2], want, pair, 1,
              "a kernel that states its level always gets its own module");
    }

    /* https://github.com/mitschud/DirtyFrag/issues/73 */
    check(17, 6, 6, "android15-6.6", 1, 0,
          "issue 73: Android 17 read against an android15-6.6 kernel still lands right");
    check(17, 5, 10, "android13-5.10", 2, 0,
          "but on an ambiguous pair a marketing version picks the nearest level, "
          "not the first row of the table");
    check(99, 5, 15, "android14-5.15", 2, 0, "absurd level still stays on the kernel line");
    check(12, 5, 15, "android13-5.15", 2, 0,
          "android12 has no 5.15 module; nearest is android13 and it is flagged inexact");
    check(11, 5, 10, "android12-5.10", 2, 0, "level below every candidate takes the closest");

    /* The fallback path failing outright must not lose the kernel line. */
    check(0, 5, 10, "android12-5.10", 2, 0,
          "no kmi at all: oldest module on the line, and the caller says so");
    check(0, 6, 6, "android15-6.6", 1, 0, "no kmi at all on a single-candidate line");

    check(13, 4, 14, NULL, 0, 0, "a non-GKI 4.14 kernel is refused, never guessed at");
    check(99, 9, 9, NULL, 0, 0, "unknown kernel version is refused");

    printf("\n%s\n", fails ? "FAILED" : "all selection cases pass");
    return fails ? 1 : 0;
}

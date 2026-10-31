/*
 * Which embedded LKM to patch into the ko_target, given what the running kernel
 * and the system properties say about the device.
 *
 * This is a header, split out of exp.c, for one reason: exp.c cannot be
 * compiled anywhere but against the Android NDK - it is page-cache patching,
 * raw symbol offsets and .incbin blobs - so the matching rules below would
 * otherwise have no test. tests/ko_select_test.c includes this file and drives
 * it with stub blobs, and CI runs it as "Native selection logic tests".
 */
#ifndef DFROOT_KO_SELECT_H
#define DFROOT_KO_SELECT_H

#include <stddef.h>

struct KoImage {
    /*
     * The GKI level the module was built for - the "androidNN" token in
     * uname -r, so "6.6.127-android15-8-..." reads as 15. This is NOT the
     * Android version the user sees. They part company on recent handsets: the
     * SM-S931B these rows were checked against reports Android 17 from
     * ro.build.version.release while booting an android15-6.6 kernel. Feeding
     * the marketing version in here picks the wrong module on any kernel line
     * that carries more than one level.
     */
    int kmi;
    int kver_major, kver_minor;
    const char *start, *end;
};

/* Defined by the .incbin block in exp.c; the host test supplies its own stubs. */
extern char dfroot_ko_12_5_10_start[],  dfroot_ko_12_5_10_end[];
extern char dfroot_ko_13_5_10_start[], dfroot_ko_13_5_10_end[];
extern char dfroot_ko_13_5_15_start[], dfroot_ko_13_5_15_end[];
extern char dfroot_ko_14_5_15_start[], dfroot_ko_14_5_15_end[];
extern char dfroot_ko_14_6_1_start[],  dfroot_ko_14_6_1_end[];
extern char dfroot_ko_15_6_6_start[],  dfroot_ko_15_6_6_end[];
extern char dfroot_ko_16_6_12_start[], dfroot_ko_16_6_12_end[];
extern char dfroot_ko_17_6_18_start[], dfroot_ko_17_6_18_end[];

static const struct KoImage dfroot_ko_images[] = {
    {12,  5, 10, dfroot_ko_12_5_10_start,  dfroot_ko_12_5_10_end},
    {13,  5, 10, dfroot_ko_13_5_10_start,  dfroot_ko_13_5_10_end},
    {13,  5, 15, dfroot_ko_13_5_15_start,  dfroot_ko_13_5_15_end},
    {14,  5, 15, dfroot_ko_14_5_15_start,  dfroot_ko_14_5_15_end},
    {14,  6,  1, dfroot_ko_14_6_1_start,   dfroot_ko_14_6_1_end},
    {15,  6,  6, dfroot_ko_15_6_6_start,   dfroot_ko_15_6_6_end},
    {16,  6, 12, dfroot_ko_16_6_12_start,  dfroot_ko_16_6_12_end},
    {17,  6, 18, dfroot_ko_17_6_18_start,  dfroot_ko_17_6_18_end},
};

#define DFROOT_KO_IMAGE_COUNT ((int)(sizeof(dfroot_ko_images) / sizeof(dfroot_ko_images[0])))

/*
 * Pick the module for a kernel version.
 *
 * The kernel version pair is the hard filter - a module built against 5.15
 * structures will not drive a 6.6 kernel - so it is matched exactly and first.
 * Two GKI levels share each of the older pairs, and there kmi decides:
 *
 *     5.10 -> android12 or android13      5.15 -> android13 or android14
 *
 * 6.1, 6.6, 6.12 and 6.18 each carry a single module, so on those a wrong kmi
 * still lands on the right image. That is the whole reason a misread Android
 * version shows up on older devices and stays invisible on newer ones.
 *
 * When kmi matches none of the candidates, the closest one by distance is used,
 * ties broken downward so the guess never overshoots the detected level. An
 * unknown kmi (<= 0) therefore gets the oldest module on that kernel line.
 * Previously the first row of the table won by position, which meant an
 * ambiguous pair silently took android12 or android13 whatever the device said.
 * Callers must treat exact == 0 as reportable and print the detected kmi
 * alongside the choice: a guessed module has to be visible in the run log.
 *
 * *candidates returns how many rows carry that kernel pair (0 = unsupported
 * kernel); *exact returns whether one of them matched kmi. NULL is returned only
 * when there are no candidates.
 */
static const struct KoImage *select_ko_image(int kmi, int major, int minor,
                                             int *candidates, int *exact)
{
    const struct KoImage *hit = NULL, *best = NULL;
    int best_dist = 0, n = 0;

    if (candidates) *candidates = 0;
    if (exact) *exact = 0;

    /* Every row is scanned even after an exact hit - *candidates is the size of
     * the ambiguity, and stopping early would understate it to the caller. */
    for (int i = 0; i < DFROOT_KO_IMAGE_COUNT; i++) {
        const struct KoImage *c = &dfroot_ko_images[i];
        int d;

        if (c->kver_major != major || c->kver_minor != minor) continue;
        n++;
        if (c->kmi == kmi) hit = c;
        d = c->kmi > kmi ? c->kmi - kmi : kmi - c->kmi;
        if (!best || d < best_dist || (d == best_dist && c->kmi < best->kmi)) {
            best = c;
            best_dist = d;
        }
    }

    if (candidates) *candidates = n;
    if (!n) return NULL;
    if (exact) *exact = (hit != NULL);
    return hit ? hit : best;
}

#endif /* DFROOT_KO_SELECT_H */

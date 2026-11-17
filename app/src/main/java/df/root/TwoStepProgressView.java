package df.root;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.view.View;

/**
 * OneUI-system-update-style two-segment progress bar.
 * Left segment: exploit run progress (0..100%), labeled with the percentage.
 * Right segment: verification step (fills during cleanup), labeled
 * "Verification" while running, then "Verified" / "Failed".
 */
public class TwoStepProgressView extends View {

    private static final int BAR_H_DP = 4;
    private static final int GAP_DP = 12;
    private static final int TRACK = 0xFF2E2E30;
    private static final int FILL = 0xFF4E8AE8;
    private static final int FILL_GREY = 0xFF2A2A2E;
    private static final int FAILED_RED = 0xFFE57373;
    private static final int LABEL_GREY = 0xFF47474A;

    private final Paint trackPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint fillPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF rect = new RectF();

    private float seg1 = 0f;
    private float seg2 = 0f;
    private String leftLabel;
    private String rightLabel;
    private int rightColor = 0xFF8E8E8E;
    private boolean failed;
    private float greyMix = 0f;
    private android.animation.ValueAnimator greyAnimator;

    public TwoStepProgressView(Context context) { this(context, null); }

    public TwoStepProgressView(Context context, AttributeSet attrs) {
        super(context, attrs);
        leftLabel = context.getString(R.string.progress_waiting);
        rightLabel = context.getString(R.string.progress_verification);
        textPaint.setTextAlign(Paint.Align.CENTER);
    }

    /** @param p 0..1 */
    public void setSeg1(float p, String label) {
        seg1 = clamp(p);
        leftLabel = label;
        invalidate();
    }

    public void setSeg2(float p, int labelRes, int labelColor) {
        seg2 = clamp(p);
        rightLabel = getContext().getString(labelRes);
        rightColor = labelColor;
        if (labelRes == R.string.progress_verified && seg1 >= 1f) {
            scheduleGreyOut();
        } else {
            cancelGreyOut();
        }
        invalidate();
    }

    /** Failure mode: bars + labels turn red (same red as the Failed text). */
    public void setFailed(boolean f) {
        failed = f;
        if (f) cancelGreyOut();
        invalidate();
    }

    public void reset() {
        cancelGreyOut();
        failed = false;
        setSeg1(0f, getContext().getString(R.string.progress_waiting));
        setSeg2(0f, R.string.progress_verification, 0xFFFFFFFF);
    }

    /** When the bar reaches 100% + Verified, ease the fill from blue to grey
     *  after a short pause so it blends into the dark UI. */
    private void scheduleGreyOut() {
        if (greyAnimator != null) return;
        greyAnimator = android.animation.ValueAnimator.ofFloat(0f, 1f);
        greyAnimator.setStartDelay(2000);
        greyAnimator.setDuration(400);
        greyAnimator.addUpdateListener(a -> {
            greyMix = (float) a.getAnimatedValue();
            invalidate();
        });
        greyAnimator.start();
    }

    private void cancelGreyOut() {
        if (greyAnimator != null) {
            greyAnimator.cancel();
            greyAnimator = null;
        }
        greyMix = 0f;
    }

    private static int mixColor(int a, int b, float t) {
        int ar = (a >> 16) & 0xFF, ag = (a >> 8) & 0xFF, ab = a & 0xFF;
        int br = (b >> 16) & 0xFF, bg = (b >> 8) & 0xFF, bb = b & 0xFF;
        return 0xFF000000
                | (Math.round(ar + (br - ar) * t) << 16)
                | (Math.round(ag + (bg - ag) * t) << 8)
                | Math.round(ab + (bb - ab) * t);
    }

    private static float clamp(float v) {
        return Math.max(0f, Math.min(1f, v));
    }

    @Override
    protected void onMeasure(int wSpec, int hSpec) {
        float d = getResources().getDisplayMetrics().density;
        setMeasuredDimension(
                resolveSize((int) (200 * d), wSpec),
                resolveSize((int) (54 * d), hSpec));
    }

    @Override
    protected void onDraw(Canvas canvas) {
        float d = getResources().getDisplayMetrics().density;
        float w = getWidth();
        float barH = BAR_H_DP * d;
        float gap = GAP_DP * d;
        float half = (w - gap) / 2f;

        // Bars. Red while failed, otherwise blue easing to grey once Verified settles.
        trackPaint.setColor(TRACK);
        fillPaint.setColor(failed ? FAILED_RED
                : mixColor(FILL, FILL_GREY, greyMix));

        rect.set(0, 0, half, barH);
        canvas.drawRoundRect(rect, barH / 2f, barH / 2f, trackPaint);
        if (seg1 > 0f) {
            rect.set(0, 0, Math.max(barH, half * seg1), barH);
            canvas.drawRoundRect(rect, barH / 2f, barH / 2f, fillPaint);
        }

        rect.set(half + gap, 0, w, barH);
        canvas.drawRoundRect(rect, barH / 2f, barH / 2f, trackPaint);
        if (seg2 > 0f) {
            rect.set(half + gap, 0, half + gap + Math.max(barH, half * seg2), barH);
            canvas.drawRoundRect(rect, barH / 2f, barH / 2f, fillPaint);
        }

        // Labels centered under each segment, dropped well below the bar.
        // NOTE: setTextSize must happen BEFORE reading ascent(), otherwise the
        // first draw uses default-size metrics and the label jumps on the
        // next render (e.g. after returning from the background).
        textPaint.setTextSize(15 * d);
        float ty = barH + 15 * d - textPaint.ascent();
        // Labels grey out together with the bars once Verified settles; both
        // turn red in failure mode.
        textPaint.setColor(mixColor(failed ? FAILED_RED : 0xFFFFFFFF,
                LABEL_GREY, greyMix));
        canvas.drawText(leftLabel, half / 2f, ty, textPaint);
        textPaint.setColor(mixColor(rightColor, LABEL_GREY, greyMix));
        canvas.drawText(rightLabel, half + gap + half / 2f, ty, textPaint);
    }
}
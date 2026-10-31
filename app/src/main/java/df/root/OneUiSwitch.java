package df.root;

import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.view.HapticFeedbackConstants;
import android.view.View;
import android.view.animation.DecelerateInterpolator;

/**
 * OneUI-style switch drawn from scratch: 46x28dp pill, constant-size 21dp
 * thumb (3.5dp margin) in both states, 160ms slide + color fade.
 */
public class OneUiSwitch extends View {

    // Geometry (dp)
    private static final float TRACK_W = 46f, TRACK_H = 28f;
    private static final float THUMB_D = 21f, MARGIN = 3.5f;

    // Colors (strictly neutral grey - monochrome UI)
    private static final int ON_TRACK = 0xFFC9C9C9,  ON_THUMB = 0xFF141414;
    private static final int OFF_TRACK = 0xFF2E2E2E, OFF_THUMB = 0xFF8E8E8E;

    private static final long ANIM_MS = 160;

    private final Paint trackPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint thumbPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF trackRect = new RectF();
    private final RectF thumbRect = new RectF();

    private boolean checked = false;
    private boolean enabledState = true;
    private float progress = 0f; // 0 = off, 1 = on

    private OnCheckedChangeListener listener;

    public interface OnCheckedChangeListener {
        void onCheckedChanged(OneUiSwitch view, boolean checked);
    }

    public OneUiSwitch(Context context) { this(context, null); }

    public OneUiSwitch(Context context, AttributeSet attrs) {
        super(context, attrs);
        setClickable(true);
        setFocusable(true);
    }

    public void setChecked(boolean checked) {
        if (this.checked == checked) return;
        this.checked = checked;
        animateTo(checked ? 1f : 0f);
        invalidate();
    }

    /**
     * A state being displayed rather than one changed under a finger: the thumb is already at
     * its end when the view appears, so sliding it there is a lie about what just happened.
     */
    public void setCheckedQuiet(boolean checked) {
        this.checked = checked;
        this.progress = checked ? 1f : 0f;
        invalidate();
    }

    public boolean isChecked() { return checked; }

    @Override
    public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
        enabledState = enabled;
        invalidate();
    }

    public void setOnCheckedChangeListener(OnCheckedChangeListener l) {
        listener = l;
    }

    private void animateTo(float target) {
        animate().cancel();
        ValueAnimator a = ValueAnimator.ofFloat(progress, target);
        a.setDuration(ANIM_MS);
        a.setInterpolator(new DecelerateInterpolator());
        a.addUpdateListener(anim -> {
            progress = (float) anim.getAnimatedValue();
            invalidate();
        });
        a.start();
    }

    @Override
    public boolean performClick() {
        if (!enabledState) return false;
        performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
        boolean next = !checked;
        setChecked(next);
        if (listener != null) listener.onCheckedChanged(this, next);
        return super.performClick();
    }

    @Override
    protected void onMeasure(int wSpec, int hSpec) {
        int w = (int) (TRACK_W * getResources().getDisplayMetrics().density);
        int h = (int) (TRACK_H * getResources().getDisplayMetrics().density);
        setMeasuredDimension(resolveSize(w, wSpec), resolveSize(h, hSpec));
    }

    @Override
    protected void onDraw(Canvas canvas) {
        float d = getResources().getDisplayMetrics().density;
        float w = getWidth(), h = getHeight();

        // Track colors fade between states; disabled renders the OFF look.
        boolean on = checked;
        int trackCol = on ? ON_TRACK : OFF_TRACK;
        int thumbCol = on ? ON_THUMB : OFF_THUMB;
        trackPaint.setColor(trackCol);
        thumbPaint.setColor(thumbCol);

        trackRect.set(0, 0, w, h);
        canvas.drawRoundRect(trackRect, h / 2f, h / 2f, trackPaint);

        float ty = MARGIN * d;
        float txTravel = w - (THUMB_D + 2 * MARGIN) * d;
        float tx = ty + txTravel * progress;
        thumbRect.set(tx, ty, tx + THUMB_D * d, ty + THUMB_D * d);
        canvas.drawRoundRect(thumbRect, THUMB_D * d / 2f, THUMB_D * d / 2f, thumbPaint);
    }
}
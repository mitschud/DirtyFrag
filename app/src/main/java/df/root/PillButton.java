package df.root;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.util.AttributeSet;
import android.view.Gravity;
import android.widget.Button;
import android.widget.TextView;

/**
 * The framework stand-in for a MaterialButton pill: a filled rounded rect with a
 * separate hairline stroke and a ripple, drawn from GradientDrawable + RippleDrawable,
 * so no com.google.android.material dependency is needed.
 *
 * It extends TextView, not Button: a framework Button arrives with the platform's own
 * button style, and OneUI's style installs a background of its own behind our back.
 * TextView carries no default style, so the only background this view owns is ours;
 * getAccessibilityClassName keeps TalkBack reading it as a button.
 *
 * The fill is that background and the press ripple is a content-less RippleDrawable in
 * the foreground, masked to the same rounded rect. Neither is wrapped inside the other:
 * a shape installed inside another drawable is copied on the way in and stops answering
 * to the object this class holds, and the fill and stroke need two colours, which one
 * tint cannot give - so setBackgroundTintList is intercepted here and answered by
 * recolouring the shape, and the tint the XML puts on the view is dropped (a tint in
 * SRC_IN replaces the shape's colour outright: with it in place the pill stayed at the
 * layout's #7A7A7A while the shape underneath was tinted #1F1F1F, then bright green).
 *
 * The radius stays constant at 27dp = half the 54dp height, so the same view reads as a
 * circle at 54dp wide and as a stadium pill once MainActivity animates the width - the
 * same trick bg_pill.xml plays for the SU-manager launcher.
 */
public class PillButton extends TextView {

    private static final int   DEFAULT_FILL   = 0xFF7A7A7A;
    private static final int   DEFAULT_STROKE = 0xFFA6A6A6;
    /** The theme's colorControlHighlight, inlined because there is no Material theme now. */
    private static final int   RIPPLE         = 0x4D6E6E6E;
    private static final float RADIUS_DP      = 27f;
    private static final float STROKE_DP      = 0.5f;

    private GradientDrawable fill;
    private float radius;
    private ColorStateList pendingTint;
    private int strokeColor = DEFAULT_STROKE;
    private int strokeWidth;

    public PillButton(Context context, AttributeSet attrs) {
        super(context, attrs);
        float density = context.getResources().getDisplayMetrics().density;

        // The behaviour a framework Button gave for free, now spelled out: centred text
        // that is not shouted in caps, a view that clicks and takes focus, and no
        // state-list animator moving elevation behind our back.
        setAllCaps(false);
        setStateListAnimator(null);
        setGravity(Gravity.CENTER);
        setClickable(true);
        setFocusable(true);

        // The app: values the layout writes on btnRun. Material read these itself; here
        // they are read the same way, so the XML still means what it says.
        TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.PillButton);
        strokeWidth = a.getDimensionPixelSize(R.styleable.PillButton_strokeWidth,
                (int) (STROKE_DP * density + 0.5f));
        strokeColor = a.getColor(R.styleable.PillButton_strokeColor, DEFAULT_STROKE);
        radius = a.getDimension(R.styleable.PillButton_cornerRadius, RADIUS_DP * density);
        a.recycle();

        fill = new GradientDrawable();
        fill.setShape(GradientDrawable.RECTANGLE);
        fill.setCornerRadius(radius);
        fill.setColor(pendingTint != null
                ? pendingTint.getColorForState(getDrawableState(), DEFAULT_FILL) : DEFAULT_FILL);
        fill.setStroke(strokeWidth, strokeColor);
        super.setBackground(fill);

        // The layout's android:backgroundTint has already been installed on the view by
        // the time this runs, and a tint in SRC_IN replaces whatever colour the shape
        // underneath carries - every recolour made afterwards is painted straight over.
        // Measured on device: the pill held the layout's #7A7A7A while the shape below
        // the tint was set to #1F1F1F, then to bright green. The shape owns the fill and
        // the stroke, so the view-side tint is dropped and never put back.
        super.setBackgroundTintList(null);
        fill.clearColorFilter();

        // The press highlight lives in the FOREGROUND as a ripple with no content of its
        // own, so the fill stays a shape this class can recolour at will. Nesting the fill
        // inside the RippleDrawable instead copies it on the way in: the shape the
        // container paints is not the shape held here, and later fill changes land on a
        // copy nobody draws. The mask keeps the ripple inside the pill's own radius.
        super.setForeground(new RippleDrawable(
                ColorStateList.valueOf(RIPPLE), null, stencil(radius)));

        // The XML backgroundTint arrived from View's own constructor, before this one had
        // built the shape; pendingTint is what setBackgroundTintList stashed away for it.
        if (pendingTint != null) applyTint(pendingTint);
        setStrokeColor(ColorStateList.valueOf(strokeColor));
    }

    /** TalkBack should still hear a button, not a label. */
    @Override
    public CharSequence getAccessibilityClassName() {
        return Button.class.getName();
    }

    /** Material's API, kept so MainActivity's four state setters stay as they
     *  were. Not an override: a plain text view has no stroke of its own, the
     *  hairline belongs to the GradientDrawable this class draws. */
    public void setStrokeColor(ColorStateList colors) {
        if (colors == null) return;
        strokeColor = colors.getColorForState(getDrawableState(), Color.TRANSPARENT);
        if (fill != null) {
            fill.setStroke(strokeWidth, strokeColor);
            invalidate();
        }
    }

    /** Fill colour, which is what setBackgroundTintList has always meant here. */
    @Override
    public void setBackgroundTintList(ColorStateList tint) {
        if (fill == null) { pendingTint = tint; return; }
        applyTint(tint);
    }

    private void applyTint(ColorStateList tint) {
        if (tint == null || fill == null) return;
        // The shape is the view's own background, so recolouring it is enough - but ask
        // the view to redraw rather than trust the drawable's invalidateSelf plumbing.
        fill.setColor(tint.getColorForState(getDrawableState(), DEFAULT_FILL));
        invalidate();
    }

    /**
     * The ripple's stencil: same rounded rect, painted opaque white because only its
     * alpha counts. It exists so the ripple is clipped to the pill without being the
     * pill's own fill.
     */
    private static GradientDrawable stencil(float radius) {
        GradientDrawable mask = new GradientDrawable();
        mask.setShape(GradientDrawable.RECTANGLE);
        mask.setCornerRadius(radius);
        mask.setColor(Color.WHITE);   // only its alpha is read; the mask never paints
        return mask;
    }

    /** Kept for the day the pill wants a different radius than half its height. */
    void setCornerRadiusPx(float px) {
        radius = px;
        if (fill != null) {
            fill.setCornerRadius(px);
            // The ripple is clipped by its own copy of the shape, so it has to follow.
            super.setForeground(new RippleDrawable(
                    ColorStateList.valueOf(RIPPLE), null, stencil(px)));
            invalidate();
        }
    }
}

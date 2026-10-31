package df.root;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.util.AttributeSet;
import android.widget.Button;

/**
 * The framework stand-in for a MaterialButton pill: a filled rounded rect with a
 * separate hairline stroke and a ripple, drawn from GradientDrawable + RippleDrawable
 * so no com.google.android.material dependency is needed.
 *
 * The two look knobs the app actually animates are the fill and the stroke. Fill is set
 * the way it always was, through setBackgroundTintList, which this class intercepts and
 * forwards to its own shape: tinting the RippleDrawable wrapper instead would be a no-op,
 * because a LayerDrawable does not push a tint down into its layers.
 *
 * The radius stays constant at 27dp = half the 54dp height, so the same view reads as a
 * circle at 54dp wide and as a stadium pill once MainActivity animates the width - the
 * same trick bg_pill.xml plays for the SU-manager launcher.
 */
public class PillButton extends Button {

    private static final int   DEFAULT_FILL   = 0xFF7A7A7A;
    private static final int   DEFAULT_STROKE = 0xFFA6A6A6;
    /** The theme's colorControlHighlight, inlined because there is no Material theme now. */
    private static final int   RIPPLE         = 0x4D6E6E6E;
    private static final float RADIUS_DP      = 27f;
    private static final float STROKE_DP      = 0.5f;

    private GradientDrawable fill;
    private ColorStateList pendingTint;
    private int strokeColor = DEFAULT_STROKE;
    private int strokeWidth;

    public PillButton(Context context, AttributeSet attrs) {
        super(context, attrs);
        float density = context.getResources().getDisplayMetrics().density;

        // A framework Button would shout (textAllCaps) and animate its own elevation;
        // the Material pill did neither.
        setAllCaps(false);
        setStateListAnimator(null);

        // The app: values the layout writes on btnRun. Material read these itself; here
        // they are read the same way, so the XML still means what it says.
        TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.PillButton);
        strokeWidth = a.getDimensionPixelSize(R.styleable.PillButton_strokeWidth,
                (int) (STROKE_DP * density + 0.5f));
        strokeColor = a.getColor(R.styleable.PillButton_strokeColor, DEFAULT_STROKE);
        float radius = a.getDimension(R.styleable.PillButton_cornerRadius, RADIUS_DP * density);
        a.recycle();

        fill = new GradientDrawable();
        fill.setShape(GradientDrawable.RECTANGLE);
        fill.setCornerRadius(radius);
        fill.setColor(pendingTint != null
                ? pendingTint.getColorForState(getDrawableState(), DEFAULT_FILL) : DEFAULT_FILL);
        fill.setStroke(strokeWidth, strokeColor);

        // Ripple clipped to the same rounded shape, so the press highlight is the 30%
        // mid-grey the theme used to supply.
        super.setBackground(new RippleDrawable(ColorStateList.valueOf(RIPPLE), fill, fill));

        if (pendingTint != null) applyTint(pendingTint);
        // The XML backgroundTint arrives from View's own constructor, before this one has
        // built the shape; remember it and apply it now.
        ColorStateList t = getBackgroundTintList();
        if (t != null) applyTint(t);
        setStrokeColor(ColorStateList.valueOf(strokeColor));
    }

    /** Material's API, kept so MainActivity's four state setters stay as they
     *  were. Not an override: a framework Button has no stroke of its own, the
     *  hairline belongs to the GradientDrawable this class draws. */
    public void setStrokeColor(ColorStateList colors) {
        if (colors == null) return;
        strokeColor = colors.getColorForState(getDrawableState(), Color.TRANSPARENT);
        if (fill != null) fill.setStroke(strokeWidth, strokeColor);
    }

    /** Fill colour, which is what setBackgroundTintList has always meant here. */
    @Override
    public void setBackgroundTintList(ColorStateList tint) {
        if (fill == null) { pendingTint = tint; return; }
        applyTint(tint);
    }

    private void applyTint(ColorStateList tint) {
        if (tint == null || fill == null) return;
        fill.setColor(tint.getColorForState(getDrawableState(), DEFAULT_FILL));
    }

    /** Kept for the day the pill wants a different radius than half its height. */
    void setCornerRadiusPx(float px) {
        if (fill != null) fill.setCornerRadius(px);
    }
}

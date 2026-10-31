package df.root;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.drawable.GradientDrawable;
import android.util.AttributeSet;
import android.widget.FrameLayout;

/**
 * OneUI card that lives inside a CardStackLayout. It owns nothing but looks:
 * the lifted look (shaded white fill, thin white outline, a shadow to sit on),
 * the slight black-out of the cards that are NOT being moved, and the small
 * shrink of the cards that have to give up their slot. There is no handle to
 * grab: hold anywhere on the card and it lifts, the way a home screen icon does.
 *
 * The gesture belongs to CardStackLayout, which is why this class only answers
 * "what should I look like?". The lifted look arrives with the lift and leaves
 * with the selection. It is deliberately not faded in or charged up first: a
 * highlight that starts animating the moment the finger lands looks like a
 * glitch and says nothing about which card is about to move.
 *
 * This used to be a MaterialCardView. The card is three attributes - a fill, a
 * corner radius and a hairline stroke - so it is now a FrameLayout whose
 * background is one GradientDrawable: the same shape gives the fill, the stroke
 * and, through the default background outline provider, the shadow the lifted
 * card casts on translationZ. activity_main.xml keeps saying cardBackgroundColor,
 * cardCornerRadius and strokeWidth; only the implementation moved (attrs.xml).
 */
public class DraggableCardView extends FrameLayout {

    private static final int REST_BG = 0xFF1C1C1C, HELD_BG = 0xFF3A3A3C;
    private static final int HELD_STROKE = 0xFFFFFFFF;
    private static final float REST_RADIUS_DP = 26f;
    private static final float STROKE_W_DP = 1.2f;
    /** How far the lifted card floats above the stack. */
    private static final float LIFT_Z_DP = 18f;
    /** "Slight black out" of the cards that are not being moved (VIS1.6). */
    private static final float DIM_ALPHA = 0.42f;
    /** Cards that make room shrink a little in every axis (VIS3.1). */
    private static final float PUSHED_SCALE = 0.94f;
    private static final long VISUAL_MS = 150;

    private final GradientDrawable shape;
    private final float density;
    private final int maxStroke;
    private final float liftZ;

    private int strokeColor = HELD_STROKE;
    private int strokeWidth;

    private boolean held, dimmed, pushed;
    private boolean hideable = true;

    public DraggableCardView(Context context) {
        this(context, null);
    }

    public DraggableCardView(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public DraggableCardView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        density = context.getResources().getDisplayMetrics().density;
        maxStroke = (int) (STROKE_W_DP * density);
        liftZ = LIFT_Z_DP * density;

        float radius = REST_RADIUS_DP * density;
        int    bg   = REST_BG;
        int    sw   = 0;
        int    sc   = HELD_STROKE;
        if (attrs != null) {
            TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.DraggableCardView);
            bg       = a.getColor(R.styleable.DraggableCardView_cardBackgroundColor, bg);
            radius   = a.getDimension(R.styleable.DraggableCardView_cardCornerRadius, radius);
            sw       = a.getDimensionPixelSize(R.styleable.DraggableCardView_strokeWidth, sw);
            sc       = a.getColor(R.styleable.DraggableCardView_strokeColor, sc);
            a.recycle();
        }

        shape = new GradientDrawable();
        shape.setShape(GradientDrawable.RECTANGLE);
        shape.setCornerRadius(radius);
        shape.setColor(bg);
        // The outline is always white; the rest state keeps a width of zero, so
        // the card stays the flat card the app has always had.
        strokeColor = sc;
        strokeWidth = sw;
        shape.setStroke(strokeWidth, strokeColor);
        super.setBackground(shape);
    }

    /** Held = lifted card: shaded white fill + thin white outline (VIS1.3). */
    public void setHeld(boolean held) {
        if (this.held == held) return;
        this.held = held;
        shape.setColor(held ? HELD_BG : REST_BG);
        strokeWidth = held ? maxStroke : 0;
        shape.setStroke(strokeWidth, strokeColor);
        setTranslationZ(held ? liftZ : 0f);
        invalidate();
    }

    public boolean isHeld() {
        return held;
    }

    /** Slight black-out so the lifted card reads as the selection (VIS1.6). */
    public void setDimmed(boolean dimmed) {
        if (this.dimmed == dimmed) return;
        this.dimmed = dimmed;
        animate().alpha(dimmed ? DIM_ALPHA : 1f).setDuration(VISUAL_MS).start();
    }

    /** Cards pushed out of the slot shrink a touch, then bounce back. */
    public void setPushed(boolean pushed) {
        if (this.pushed == pushed) return;
        this.pushed = pushed;
        float s = pushed ? PUSHED_SCALE : 1f;
        animate().scaleX(s).scaleY(s).setDuration(VISUAL_MS).start();
    }

    /** The SU Manager card moves but can never be hidden. */
    public boolean isHideable() {
        return hideable;
    }

    public void setHideable(boolean hideable) {
        this.hideable = hideable;
    }

    /** Kept for parity with MaterialCardView in case a card ever wants its own colour. */
    public void setCardBackgroundColor(int color) {
        shape.setColor(color);
        invalidate();
    }

    public void setStrokeColor(ColorStateList colors) {
        if (colors == null) return;
        strokeColor = colors.getColorForState(getDrawableState(), strokeColor);
        shape.setStroke(strokeWidth, strokeColor);
        invalidate();
    }

    public void setStrokeWidth(int px) {
        strokeWidth = px;
        shape.setStroke(strokeWidth, strokeColor);
        invalidate();
    }
}

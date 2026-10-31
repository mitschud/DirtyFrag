package df.root;

import android.view.LayoutInflater;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toolbar;

/**
 * Hand-written stand-in for the viewbinding class AGP used to generate. Every
 * binding.&lt;id&gt; call site in MainActivity keeps working and only the import and the
 * inflate line changed, but the app no longer depends on
 * androidx.databinding:viewbinding.
 *
 * Each field is resolved once here, at inflate time, which is exactly what the
 * generated code did. A missing id throws at inflation rather than showing up as a
 * compile error, so the list below has to stay in step with activity_main.xml.
 */
final class ActivityMainBinding {

    private final RelativeLayout root;

    final FrameLayout          appBarLayout;
    final BottomFadeView       bottomFade;
    final FrameLayout          btnKsu;
    final ImageButton          btnMenu;
    final PillButton           btnRun;
    final ImageButton          btnShareLog;
    final DraggableCardView    cardBoot;
    final DraggableCardView    cardLog;
    final DraggableCardView    cardModules;
    final DraggableCardView    cardSuManager;
    final CardStackLayout      cardStack;
    final ImageView            chevronSuManager;
    final View                 dimOverlay;
    final ImageView            ksuChevron;
    final TextView             ksuLabel;
    final FrameLayout          logWindow;
    final TextView             modulesSubtitle;
    final View                 odinDot;
    final TextView             odinLabel;
    final LinearLayout         odinPill;
    final ScrollView           outputScroll;
    final TextView             outputView;
    final LinearLayout         rowSuManager;
    final TextView             suManagerSubtitle;
    final OneUiSwitch          switchAdvancedLog;
    final OneUiSwitch          switchAutoSoftReboot;
    final OneUiSwitch          switchBootStart;
    final OneUiSwitch          switchModules;
    final Toolbar              toolbar;
    final TextView             tvAutorunDesc;
    final TextView             tvAutorunTitle;
    final TextView             tvRebootDesc;
    final TextView             tvRebootTitle;
    final TwoStepProgressView  twoStep;
    final TextView             updateLabel;
    final FrameLayout          updatePill;
    final View                 menuAnchor;

    private ActivityMainBinding(View inflated) {
        this.root = (RelativeLayout) inflated;
        appBarLayout       = inflated.findViewById(R.id.appBarLayout);
        bottomFade         = inflated.findViewById(R.id.bottomFade);
        btnKsu             = inflated.findViewById(R.id.btnKsu);
        btnMenu            = inflated.findViewById(R.id.btnMenu);
        btnRun             = inflated.findViewById(R.id.btnRun);
        btnShareLog        = inflated.findViewById(R.id.btnShareLog);
        cardBoot           = inflated.findViewById(R.id.cardBoot);
        cardLog            = inflated.findViewById(R.id.cardLog);
        cardModules        = inflated.findViewById(R.id.cardModules);
        cardSuManager      = inflated.findViewById(R.id.cardSuManager);
        cardStack          = inflated.findViewById(R.id.cardStack);
        chevronSuManager   = inflated.findViewById(R.id.chevronSuManager);
        dimOverlay         = inflated.findViewById(R.id.dimOverlay);
        ksuChevron         = inflated.findViewById(R.id.ksuChevron);
        ksuLabel           = inflated.findViewById(R.id.ksuLabel);
        logWindow          = inflated.findViewById(R.id.logWindow);
        menuAnchor         = inflated.findViewById(R.id.menuAnchor);
        modulesSubtitle    = inflated.findViewById(R.id.modulesSubtitle);
        odinDot            = inflated.findViewById(R.id.odinDot);
        odinLabel          = inflated.findViewById(R.id.odinLabel);
        odinPill           = inflated.findViewById(R.id.odinPill);
        outputScroll       = inflated.findViewById(R.id.outputScroll);
        outputView         = inflated.findViewById(R.id.outputView);
        rowSuManager       = inflated.findViewById(R.id.rowSuManager);
        suManagerSubtitle  = inflated.findViewById(R.id.suManagerSubtitle);
        switchAdvancedLog  = inflated.findViewById(R.id.switchAdvancedLog);
        switchAutoSoftReboot = inflated.findViewById(R.id.switchAutoSoftReboot);
        switchBootStart    = inflated.findViewById(R.id.switchBootStart);
        switchModules      = inflated.findViewById(R.id.switchModules);
        toolbar            = inflated.findViewById(R.id.toolbar);
        tvAutorunDesc      = inflated.findViewById(R.id.tvAutorunDesc);
        tvAutorunTitle     = inflated.findViewById(R.id.tvAutorunTitle);
        tvRebootDesc       = inflated.findViewById(R.id.tvRebootDesc);
        tvRebootTitle      = inflated.findViewById(R.id.tvRebootTitle);
        twoStep            = inflated.findViewById(R.id.twoStep);
        updateLabel        = inflated.findViewById(R.id.updateLabel);
        updatePill         = inflated.findViewById(R.id.updatePill);
    }

    static ActivityMainBinding inflate(LayoutInflater inflater) {
        return new ActivityMainBinding(inflater.inflate(R.layout.activity_main, null));
    }

    RelativeLayout getRoot() {
        return root;
    }
}

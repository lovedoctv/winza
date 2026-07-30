# WINZA mobile (Capacitor wrapper)

This is a thin native shell around the live WINZA site — it does not bundle
its own copy of `winza.html` or any backend logic. On launch it loads
`server.url` from `capacitor.config.json` directly, so all API/auth/wallet
behavior is identical to the website and updates automatically whenever the
Render web service is redeployed. No app-store resubmission is needed for
ordinary site changes — only for native-level changes (icons, permissions,
plugins, the target URL itself).

Currently points at: `https://winza-gjl6.onrender.com`

## Switching to a custom domain later

Once `winza.africa` is bought and pointed at the Render web service (Render
dashboard → your service → Settings → Custom Domains), update one line:

```json
// capacitor.config.json
"server": { "url": "https://winza.africa", ... }
```

then run `npx cap sync` and rebuild. Nothing else changes.

## Building — Android

Requires [Android Studio](https://developer.android.com/studio) (this repo's
sandbox has no Android SDK, so the build itself has to happen on your machine
or in CI).

```
cd mobile
npm install
npx cap open android
```

That opens the `android/` project in Android Studio. From there:
- **Test on a device/emulator**: Run ▶ as normal.
- **Release build**: Build > Generate Signed Bundle/APK, choose Android App
  Bundle (`.aab` — what Play Store wants), and create/select a signing
  keystore. **Back up that keystore file and its password somewhere safe —
  losing it means you can never update this app listing again.**

## Building — iOS (requires a Mac)

```
cd mobile
npm install
npx cap open ios
```

Opens `ios/App/App.xcworkspace` in Xcode. You'll need:
- CocoaPods (`sudo gem install cocoapods`) if Xcode prompts for a pod install.
- An Apple Developer account (paid, $99/yr) to sign and submit.
- Product > Archive, then use the Organizer to upload to App Store Connect.

## App icon & splash screen

Currently using Capacitor's default placeholder assets. To generate real ones
from a single source image, use `@capacitor/assets`:

```
npm install -D @capacitor/assets
npx capacitor-assets generate
```

Drop a 1024x1024 `icon.png` (and optionally a `splash.png`) in `mobile/resources/`
first — see https://capacitorjs.com/docs/guides/splash-screens-and-icons.

## Real-money gambling: store-specific requirements

Independent of anything technical here — this is a real-money gambling app
licensed for Nigeria (Oyo State gaming license). Both stores have their own
review process for that category, separate from normal app review:

- **Google Play**: real-money gambling apps need a separate Play Console
  request/permission and are only permitted in specific countries — confirm
  Nigeria is currently on that list before submitting, and be ready to
  provide license documentation.
- **Apple App Store**: real-money gaming apps are restricted to specific
  approved regions and require the developer account to be an organization
  (not individual), plus proof of licensing for each region the app targets.

Check both platforms' current gambling policy pages before submitting —
these rules change and neither store's list of eligible countries is fixed.

## Config reference

- `capacitor.config.json` — `appId` (`com.winza.app`, permanent once
  published), `appName` (shown under the icon), `server.url` (what loads on
  launch).
- `android/` and `ios/` — generated native projects; safe to delete and
  regenerate with `npx cap add android` / `npx cap add ios` if they ever get
  out of sync (uncommitted native customizations would be lost, so check
  `git status` in there first).

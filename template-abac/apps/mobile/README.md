# @kalekit/mobile

The **Local** app — Expo / React Native, iOS + Android.

Native (not mobile web) because push notifications and background photo upload
don't work reliably on mobile web, and a missed assignment alert is lost supply.

## Builds

Expo Go is **not** usable — WebRTC (live call) and background upload require a
custom dev client. Use EAS Build from week one:

```bash
pnpm --filter @kalekit/mobile dev            # Metro, for a dev client build
eas build --profile development --platform ios
eas build --profile production --platform all
eas update --channel production            # OTA JS bundle
```

## Runtime versions

`app.json` uses `runtimeVersion.policy = "fingerprint"`. OTA updates only reach
binaries with a matching runtime — pushing a bundle to a mismatched native
runtime crashes the app. Get this right from the first binary.

## Not in CI here

Builds and updates run through EAS, not this repo's GitHub Actions. Fill in
`PROJECT_ID_HERE` in `app.json` after `eas init`.

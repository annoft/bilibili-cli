# Changelog

## 0.6.3

- Disable automatic browser-cookie extraction in normal authentication paths; retain the implementation for future opt-in work
- Keep QR login write-capability checks and use saved-credential validation for active authentication

## 0.5.0

- Add subtitle timeline output via `bili video --subtitle-timeline` / `-st`
- Add `--subtitle-format timeline|srt`
- Keep subtitle timeline compatible with current `--yaml` / `--json` command surface
- Ensure subtitle timeline requests load optional credentials like plain subtitles
- Restore README badges and fix CI type-checking with `types-PyYAML`

# SentinelBot video

A ~2 to 3 minute explainer video built with [Remotion](https://remotion.dev), in English and Persian. Every number and screen shown in it comes from the real project (`docs/results/`, `docs/laboratory-experiments.md`, `docs/evaluation.md`) — nothing is invented.

The visuals are code (no screen recording needed). You record the narration yourself; each scene's length automatically matches the length of your recording.

## 1. Install

```bash
cd video
npm install
```

## 2. Preview without recording anything

The project ships with 4-second silent placeholder clips in `public/audio/en/` and `public/audio/fa/`, so you can open the Studio and see the visuals immediately:

```bash
npm start
```

This opens Remotion Studio in the browser. Pick `SentinelBotEN` or `SentinelBotFA` from the sidebar.

## 3. Record the narration

Read each line below aloud, in one take if you can, at a natural pace — don't rush to hit a time target, the video adapts to you. Save each as an **mp3** (or wav/ogg — Remotion plays all of them) at the exact path shown. A phone voice memo app or OBS works fine; just keep it reasonably quiet and consistent in volume across clips.

Full text is also in [`src/script.ts`](src/script.ts) (`narration.en` / `narration.fa` per scene) if you want it in one file to read from.

| # | File (English) | File (Persian) | Read this |
| - | - | - | - |
| 1 | `public/audio/en/scene-1.mp3` | `public/audio/fa/scene-1.mp3` | **EN:** SentinelBot. A transparent security monitoring pipeline for Linux servers.<br>**FA:** سنتینل‌بات. یک پایپ‌لاین شفاف برای مانیتورینگ امنیتی سرورهای لینوکس. |
| 2 | `scene-2.mp3` | `scene-2.mp3` | **EN:** Internet facing Linux servers get hit by constant SSH guessing. Buried in thousands of log lines, a real attack looks just like noise, unless something is actually watching.<br>**FA:** سرورهای لینوکسی که روی اینترنت باز هستند، دائم هدف حدس زدن رمز اس‌اس‌اچ قرار می‌گیرند. وسط هزاران خط لاگ، یک حمله واقعی دقیقا شبیه نویز است، مگر اینکه واقعا کسی داشته باشد نگاه کند. |
| 3 | `scene-3.mp3` | `scene-3.mp3` | **EN:** An agent on each host reads the journal, turns log lines into typed events, and sends them to a server. The server runs detection, scores the risk, correlates related detections into one incident, and shows it on a dashboard.<br>**FA:** روی هر سرور یک ایجنت لاگ‌ها را می‌خواند، به رویدادهای ساختاریافته تبدیل می‌کند و برای سرور می‌فرستد. سرور قوانین تشخیص را اجرا می‌کند، ریسک را امتیاز می‌دهد، تشخیص‌های مرتبط را در یک رخداد ترکیب می‌کند و روی داشبورد نشان می‌دهد. |
| 4 | `scene-4.mp3` | `scene-4.mp3` | **EN:** Here is a real run. Eight failed SSH logins from one address. The rule fires once it crosses five failures in five minutes, and it stays quiet after that, so one attack does not flood the dashboard with duplicates.<br>**FA:** این یک اجرای واقعی است. هشت تلاش ناموفق اس‌اس‌اچ از یک آدرس. قانون وقتی تعداد از پنج در پنج دقیقه رد شود فعال می‌شود، و بعدش ساکت می‌ماند، تا یک حمله داشبورد را پر از هشدار تکراری نکند. |
| 5 | `scene-5.mp3` | `scene-5.mp3` | **EN:** When that same address logs in as root three minutes later, the two detections merge into one incident, with a risk score of sixty, built from three named, explainable factors.<br>**FA:** وقتی همان آدرس سه دقیقه بعد با روت لاگین می‌کند، دو تشخیص در یک رخداد ترکیب می‌شوند، با امتیاز ریسک شصت، که از سه فاکتور نام‌دار و قابل‌توضیح ساخته شده است. |
| 6 | `scene-6.mp3` | `scene-6.mp3` | **EN:** An optional AI analyst can explain the incident in plain language, but it only reads the facts the rules already found. It never decides that an attack happened.<br>**FA:** یک تحلیلگر هوش مصنوعی اختیاری می‌تواند رخداد را به زبان ساده توضیح دهد، ولی فقط فکت‌هایی را می‌خواند که قوانین از قبل پیدا کرده‌اند. هیچ‌وقت خودش تصمیم نمی‌گیرد که حمله‌ای اتفاق افتاده است. |
| 7 | `scene-7.mp3` | `scene-7.mp3` | **EN:** Everything here is measured, not assumed. Eighty nine detection tests pass. The pipeline processes about twenty one thousand log lines a second, offline. And what has not been measured yet, like accuracy on real attacks, is marked exactly that: not yet measured.<br>**FA:** همه این‌ها اندازه‌گیری شده‌اند، نه فرض. هشتاد و نه تست تشخیص پاس می‌شوند. پایپ‌لاین حدود بیست و یک هزار خط لاگ در ثانیه، به‌صورت آفلاین پردازش می‌کند. و چیزهایی که هنوز اندازه‌گیری نشده‌اند، مثل دقت روی حملات واقعی، دقیقا همین‌طور علامت خورده‌اند: هنوز اندازه‌گیری نشده. |
| 8 | `scene-8.mp3` | `scene-8.mp3` | **EN:** SentinelBot. Open source, documented, and honest about its limits. Link in the description.<br>**FA:** سنتینل‌بات. متن‌باز، مستند، و صادق درباره محدودیت‌هایش. لینک در توضیحات. |

Replace the matching placeholder file in `public/audio/en/` or `public/audio/fa/` with your recording (same filename). You don't have to do both languages at once — `SentinelBotEN` only reads from `public/audio/en/`, `SentinelBotFA` only from `public/audio/fa/`.

Tips:
- Record somewhere quiet; a closet full of clothes or a small room with soft furnishing beats an echoey room.
- Keep the mic 15-20 cm away and off to the side a little, to soften "p" and "b" pops.
- Leave half a second of silence at the start and end of each clip — the video already adds its own small pad, but a clean take avoids an abrupt cut.
- If a take is bad, just re-record that one scene's file. You don't need to redo the others.

## 4. Preview with your real narration

```bash
npm start
```

Reopen (or refresh) the composition in Studio — each scene now stretches or shrinks to match your recording's length automatically (see `calculateMetadata` in `src/Root.tsx`).

## 5. Render

```bash
npm run render:en     # -> out/sentinelbot-en.mp4
npm run render:fa     # -> out/sentinelbot-fa.mp4
npm run render:all    # both
```

Rendering uses your system's installed Chrome (`remotion.config.ts`) instead of downloading Remotion's own copy, because this machine's sandbox could not complete that download. If you render on a different machine and hit a "could not download Chrome Headless Shell" error, either let it download (needs working internet) or edit the `Config.setBrowserExecutable(...)` path in `remotion.config.ts` to point at your installed Chrome or Edge.

## What's already verified

This project was rendered end-to-end with the placeholder silent clips before being handed off — both `SentinelBotEN` and `SentinelBotFA` render without errors, all 8 scenes, transitions, and the bilingual captions. What's left is only swapping in your real narration.

## Project layout

```
video/
├── src/
│   ├── script.ts          # narration + on-screen captions, source of truth
│   ├── Root.tsx            # the 2 compositions (EN/FA) + duration calculation
│   ├── Video.tsx            # scene sequencing, transitions, audio wiring
│   ├── theme.ts             # colors/fonts
│   ├── durations.ts         # reads each audio file's length
│   ├── components/          # Caption, Panel, useEnter (shared helpers)
│   └── scenes/               # one file per scene (Title, Problem, Architecture, …)
├── public/audio/en/         # your English recordings go here
├── public/audio/fa/         # your Persian recordings go here
└── out/                      # rendered .mp4 files (gitignored)
```

## Changing anything

- **Wording**: edit `src/script.ts` (`narration` for voiceover text, `caption` for the short on-screen text — captions are not read aloud, so reword them freely without re-recording).
- **Numbers/claims**: everything shown (85/89/115 tests, ~21,000 lines/sec, risk score 60, the 8-failure example) is pulled from `docs/results/` and `docs/laboratory-experiments.md`. If those change, update the scene components in `src/scenes/` to match — don't let the video drift from what's actually measured.
- **Visuals/colors**: `src/theme.ts`.
- **Pacing**: `HEAD_PAD_SECONDS` / `TAIL_PAD_SECONDS` in `src/durations.ts`, and `TRANSITION_FRAMES` in `src/Video.tsx`.

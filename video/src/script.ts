export type SceneId =
  | "title"
  | "problem"
  | "architecture"
  | "detection"
  | "correlation"
  | "ai"
  | "evaluation"
  | "closing";

export type Scene = {
  id: number;
  key: SceneId;
  // Full narration text. Read this aloud and save the recording as
  // public/audio/<lang>/scene-<id>.mp3 — see video/README.md.
  narration: { en: string; fa: string };
  // Short on-screen headline (not read aloud, just shown as a caption).
  caption: { en: string; fa: string };
};

export const VOICE_ID = "3c9d6053-6334-592c-8997-4e325286af3f";

export const script: { scenes: Scene[] } = {
  scenes: [
    {
      id: 1,
      key: "title",
      narration: {
        en: "SentinelBot. A transparent security monitoring pipeline for Linux servers.",
        fa: "سنتینل‌بات. یک پایپ‌لاین شفاف برای مانیتورینگ امنیتی سرورهای لینوکس.",
      },
      caption: {
        en: "Transparent Linux security monitoring",
        fa: "مانیتورینگ امنیتی شفاف برای لینوکس",
      },
    },
    {
      id: 2,
      key: "problem",
      narration: {
        en: "Internet facing Linux servers get hit by constant SSH guessing. Buried in thousands of log lines, a real attack looks just like noise, unless something is actually watching.",
        fa: "سرورهای لینوکسی که روی اینترنت باز هستند، دائم هدف حدس زدن رمز اس اس اچ قرار می گیرند. وسط هزاران خط لاگ، یک حمله واقعی دقیقا شبیه نویز است، مگر اینکه واقعا کسی داشته باشد نگاه کند.",
      },
      caption: {
        en: "An attack hides in thousands of log lines",
        fa: "حمله وسط هزاران خط لاگ پنهان است",
      },
    },
    {
      id: 3,
      key: "architecture",
      narration: {
        en: "An agent on each host reads the journal, turns log lines into typed events, and sends them to a server. The server runs detection, scores the risk, correlates related detections into one incident, and shows it on a dashboard.",
        fa: "روی هر سرور یک ایجنت لاگ ها را می خواند، به رویدادهای ساختاریافته تبدیل می کند و برای سرور می فرستد. سرور قوانین تشخیص را اجرا می کند، ریسک را امتیاز می دهد، تشخیص های مرتبط را در یک رخداد ترکیب می کند و روی داشبورد نشان می دهد.",
      },
      caption: {
        en: "Agent → Detection → Score → Correlation → Dashboard",
        fa: "ایجنت ← تشخیص ← امتیاز ← گروه‌بندی ← داشبورد",
      },
    },
    {
      id: 4,
      key: "detection",
      narration: {
        en: "Here is a real run. Eight failed SSH logins from one address. The rule fires once it crosses five failures in five minutes, and it stays quiet after that, so one attack does not flood the dashboard with duplicates.",
        fa: "این یک اجرای واقعی است. هشت تلاش ناموفق اس اس اچ از یک آدرس. قانون وقتی تعداد از پنج در پنج دقیقه رد شود فعال می شود، و بعدش ساکت می ماند، تا یک حمله داشبورد را پر از هشدار تکراری نکند.",
      },
      caption: {
        en: "5 failures in 5 minutes → one detection",
        fa: "۵ خطا در ۵ دقیقه ← یک تشخیص",
      },
    },
    {
      id: 5,
      key: "correlation",
      narration: {
        en: "When that same address logs in as root three minutes later, the two detections merge into one incident, with a risk score of sixty, built from three named, explainable factors.",
        fa: "وقتی همان آدرس سه دقیقه بعد با روت لاگین می کند، دو تشخیص در یک رخداد ترکیب می شوند، با امتیاز ریسک شصت، که از سه فاکتور نام دار و قابل توضیح ساخته شده است.",
      },
      caption: {
        en: "Two detections → one incident, risk 60",
        fa: "دو تشخیص ← یک رخداد، ریسک ۶۰",
      },
    },
    {
      id: 6,
      key: "ai",
      narration: {
        en: "An optional AI analyst can explain the incident in plain language, but it only reads the facts the rules already found. It never decides that an attack happened.",
        fa: "یک تحلیلگر هوش مصنوعی اختیاری می تواند رخداد را به زبان ساده توضیح دهد، ولی فقط فکت هایی را می خواند که قوانین از قبل پیدا کرده اند. هیچ وقت خودش تصمیم نمی گیرد که حمله ای اتفاق افتاده است.",
      },
      caption: {
        en: "AI explains the evidence. It never decides.",
        fa: "هوش مصنوعی شواهد را توضیح می‌دهد، نه تصمیم می‌گیرد",
      },
    },
    {
      id: 7,
      key: "evaluation",
      narration: {
        en: "Everything here is measured, not assumed. Eighty nine detection tests pass. The pipeline processes about twenty one thousand log lines a second, offline. And what has not been measured yet, like accuracy on real attacks, is marked exactly that: not yet measured.",
        fa: "همه این ها اندازه گیری شده اند، نه فرض. هشتاد و نه تست تشخیص پاس می شوند. پایپ‌لاین حدود بیست و یک هزار خط لاگ در ثانیه، به صورت آفلاین پردازش می کند. و چیزهایی که هنوز اندازه گیری نشده اند، مثل دقت روی حملات واقعی، دقیقا همین طور علامت خورده اند: هنوز اندازه گیری نشده.",
      },
      caption: {
        en: "85 + 89 + 115 tests passing. Honest about limits.",
        fa: "۸۵ + ۸۹ + ۱۱۵ تست موفق. صادق درباره‌ی محدودیت‌ها",
      },
    },
    {
      id: 8,
      key: "closing",
      narration: {
        en: "SentinelBot. Open source, documented, and honest about its limits. Link in the description.",
        fa: "سنتینل‌بات. متن باز، مستند، و صادق درباره محدودیت هایش. لینک در توضیحات.",
      },
      caption: {
        en: "Open source on GitHub",
        fa: "متن‌باز روی گیت‌هاب",
      },
    },
  ],
};

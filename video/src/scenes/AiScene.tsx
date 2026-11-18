import React from "react";
import { AbsoluteFill, interpolate } from "remotion";
import { theme } from "../theme";
import { Panel } from "../components/Panel";
import { useEnter } from "../components/useEnter";
import { Caption } from "../components/Caption";
import type { Scene } from "../script";
import type { Lang } from "../Video";

const STEPS: Record<Lang, string[]> = {
  en: ["Evidence", "Rule-based detection", "Correlation", "Risk score"],
  fa: ["شواهد", "تشخیص قانون‌محور", "گروه‌بندی", "امتیاز ریسک"],
};

export const AiScene: React.FC<{ scene: Scene; lang: Lang }> = ({ scene, lang }) => {
  const chain = useEnter(0);
  const ai = useEnter(28);
  const steps = STEPS[lang];

  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center" }}>
      <div
        style={{
          display: "flex",
          flexDirection: lang === "fa" ? "row-reverse" : "row",
          alignItems: "center",
          gap: 14,
          opacity: chain,
        }}
      >
        {steps.map((step, i) => (
          <React.Fragment key={step}>
            <div
              style={{
                fontFamily: theme.mono,
                fontSize: 20,
                color: theme.dim,
                border: `1px solid ${theme.panelBorder}`,
                borderRadius: 10,
                padding: "10px 16px",
              }}
            >
              {step}
            </div>
            {i < steps.length - 1 && <span style={{ color: theme.dim }}>→</span>}
          </React.Fragment>
        ))}
      </div>

      <div
        style={{
          width: 820,
          height: 2,
          background: `repeating-linear-gradient(90deg, ${theme.panelBorder} 0 10px, transparent 10px 18px)`,
          margin: "26px 0",
          opacity: chain,
        }}
      />

      <Panel
        style={{
          width: 820,
          padding: 28,
          opacity: ai,
          transform: `translateY(${interpolate(ai, [0, 1], [18, 0])}px)`,
          border: `1px solid ${theme.accent2}`,
        }}
      >
        <div
          style={{
            color: theme.accent2,
            fontFamily: theme.mono,
            fontSize: 16,
            marginBottom: 10,
            direction: lang === "fa" ? "rtl" : "ltr",
          }}
        >
          {lang === "fa" ? "تحلیلگر هوش مصنوعی (اختیاری)" : "AI analyst (optional)"}
        </div>
        <div
          style={{
            color: theme.text,
            fontSize: 22,
            lineHeight: 1.6,
            direction: lang === "fa" ? "rtl" : "ltr",
            textAlign: lang === "fa" ? "right" : "left",
          }}
        >
          {lang === "fa"
            ? "ورودی فقط فکت‌های ساختاریافته‌اند. خروجی اعتبارسنجی می‌شود و هیچ‌گاه وضعیت یا شدت را تغییر نمی‌دهد."
            : "The input is only structured facts. The output is validated, and it never changes status or severity."}
        </div>
      </Panel>

      <Caption text={scene.caption[lang]} lang={lang} />
    </AbsoluteFill>
  );
};

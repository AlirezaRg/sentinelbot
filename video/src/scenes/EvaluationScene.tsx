import React from "react";
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { theme } from "../theme";
import { Panel } from "../components/Panel";
import { useEnter } from "../components/useEnter";
import { Caption } from "../components/Caption";
import type { Scene } from "../script";
import type { Lang } from "../Video";

const STATS: { value: string; label: Record<Lang, string> }[] = [
  { value: "85", label: { en: "agent tests passing", fa: "تست agent موفق" } },
  { value: "89", label: { en: "detection tests passing", fa: "تست تشخیص موفق" } },
  { value: "115", label: { en: "backend tests passing", fa: "تست backend موفق" } },
  { value: "~21,000", label: { en: "log lines / sec, offline", fa: "خط لاگ در ثانیه، آفلاین" } },
];

export const EvaluationScene: React.FC<{ scene: Scene; lang: Lang }> = ({ scene, lang }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const tag = useEnter(55);

  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center" }}>
      <div style={{ display: "flex", gap: 22 }}>
        {STATS.map((stat, i) => {
          const enter = spring({
            frame: Math.max(frame - i * 7, 0),
            fps,
            config: { damping: 200 },
            durationInFrames: 16,
          });
          return (
            <Panel
              key={stat.value}
              style={{
                width: 260,
                padding: "26px 20px",
                textAlign: "center",
                opacity: enter,
                transform: `translateY(${interpolate(enter, [0, 1], [18, 0])}px)`,
              }}
            >
              <div style={{ color: theme.accent, fontSize: 40, fontWeight: 800 }}>{stat.value}</div>
              <div style={{ color: theme.dim, fontSize: 16, marginTop: 8, fontFamily: theme.mono }}>
                {stat.label[lang]}
              </div>
            </Panel>
          );
        })}
      </div>

      <div
        style={{
          marginTop: 30,
          opacity: tag,
          fontFamily: theme.mono,
          fontSize: 18,
          color: theme.warn,
          border: `1px solid ${theme.warn}`,
          borderRadius: 10,
          padding: "10px 20px",
        }}
      >
        {lang === "fa"
          ? "دقت روی حملات واقعی: هنوز اندازه‌گیری نشده"
          : "Accuracy on real attacks: NOT YET MEASURED"}
      </div>

      <Caption text={scene.caption[lang]} lang={lang} />
    </AbsoluteFill>
  );
};

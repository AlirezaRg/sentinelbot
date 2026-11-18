import React from "react";
import { AbsoluteFill, interpolate } from "remotion";
import { theme } from "../theme";
import { useEnter } from "../components/useEnter";
import type { Scene } from "../script";
import type { Lang } from "../Video";

export const ClosingScene: React.FC<{ scene: Scene; lang: Lang }> = ({ scene, lang }) => {
  const enter = useEnter(0);
  const sub = useEnter(16);

  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center" }}>
      <div
        style={{
          opacity: enter,
          transform: `scale(${interpolate(enter, [0, 1], [0.94, 1])})`,
          textAlign: "center",
          fontFamily: theme.sans,
          fontSize: 80,
          fontWeight: 800,
          color: theme.text,
        }}
      >
        Sentinel<span style={{ color: theme.accent }}>Bot</span>
      </div>

      <div
        style={{
          marginTop: 14,
          opacity: sub,
          transform: `translateY(${interpolate(sub, [0, 1], [12, 0])}px)`,
          color: theme.dim,
          fontFamily: theme.mono,
          fontSize: 24,
          direction: lang === "fa" ? "rtl" : "ltr",
        }}
      >
        {scene.caption[lang]}
      </div>

      <div
        style={{
          marginTop: 26,
          opacity: sub,
          color: theme.accent2,
          fontFamily: theme.mono,
          fontSize: 22,
        }}
      >
        github.com/AlirezaRg/sentinelbot
      </div>
    </AbsoluteFill>
  );
};

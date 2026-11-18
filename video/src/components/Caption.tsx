import React from "react";
import { interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { theme } from "../theme";
import type { Lang } from "../Video";

export const Caption: React.FC<{ text: string; lang: Lang }> = ({ text, lang }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const enter = spring({ frame, fps, config: { damping: 200 }, durationInFrames: 18 });
  const translateY = interpolate(enter, [0, 1], [24, 0]);

  return (
    <div
      style={{
        position: "absolute",
        bottom: 90,
        left: 100,
        right: 100,
        textAlign: "center",
        opacity: enter,
        transform: `translateY(${translateY}px)`,
        direction: lang === "fa" ? "rtl" : "ltr",
      }}
    >
      <span
        style={{
          display: "inline-block",
          padding: "16px 36px",
          borderRadius: 14,
          background: "rgba(13, 21, 34, 0.78)",
          border: `1px solid ${theme.panelBorder}`,
          color: theme.text,
          fontFamily: lang === "fa" ? "Vazirmatn, Tahoma, sans-serif" : theme.sans,
          fontSize: lang === "fa" ? 34 : 32,
          fontWeight: 600,
          letterSpacing: lang === "fa" ? 0 : 0.2,
        }}
      >
        {text}
      </span>
    </div>
  );
};

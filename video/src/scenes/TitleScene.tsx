import React from "react";
import { AbsoluteFill, interpolate } from "remotion";
import { theme } from "../theme";
import { useEnter } from "../components/useEnter";
import { Caption } from "../components/Caption";
import type { Scene } from "../script";
import type { Lang } from "../Video";

const PIPELINE = ["Agent", "Detect", "Score", "Correlate", "Alert"];

export const TitleScene: React.FC<{ scene: Scene; lang: Lang }> = ({ scene, lang }) => {
  const enter = useEnter(0);
  const scale = interpolate(enter, [0, 1], [0.9, 1]);
  const rowEnter = useEnter(18);

  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center" }}>
      <div style={{ opacity: enter, transform: `scale(${scale})`, textAlign: "center" }}>
        <div
          style={{
            fontFamily: theme.sans,
            fontSize: 112,
            fontWeight: 800,
            color: theme.text,
            letterSpacing: -1,
          }}
        >
          Sentinel<span style={{ color: theme.accent }}>Bot</span>
        </div>
        <div
          style={{
            marginTop: 10,
            height: 4,
            width: 220,
            background: `linear-gradient(90deg, ${theme.accent}, ${theme.accent2})`,
            marginLeft: "auto",
            marginRight: "auto",
            borderRadius: 2,
          }}
        />
      </div>

      <div
        style={{
          marginTop: 56,
          display: "flex",
          gap: 18,
          opacity: rowEnter,
          transform: `translateY(${interpolate(rowEnter, [0, 1], [16, 0])}px)`,
        }}
      >
        {PIPELINE.map((step, i) => (
          <React.Fragment key={step}>
            <div
              style={{
                fontFamily: theme.mono,
                fontSize: 22,
                color: theme.dim,
                border: `1px solid ${theme.panelBorder}`,
                borderRadius: 10,
                padding: "10px 18px",
                background: theme.panel,
              }}
            >
              {step}
            </div>
            {i < PIPELINE.length - 1 && (
              <div style={{ color: theme.accent2, fontSize: 22, alignSelf: "center" }}>→</div>
            )}
          </React.Fragment>
        ))}
      </div>

      <Caption text={scene.caption[lang]} lang={lang} />
    </AbsoluteFill>
  );
};

import React from "react";
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { theme } from "../theme";
import { Caption } from "../components/Caption";
import type { Scene } from "../script";
import type { Lang } from "../Video";

const STAGES = [
  { label: "Linux host", sub: "journal / auth.log" },
  { label: "Agent", sub: "parse → Event" },
  { label: "API", sub: "ingest" },
  { label: "Detection + Score", sub: "5 rules" },
  { label: "Correlation", sub: "→ incident" },
  { label: "Dashboard", sub: "+ alerts" },
];

export const ArchitectureScene: React.FC<{ scene: Scene; lang: Lang }> = ({ scene, lang }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 0 }}>
        {STAGES.map((stage, i) => {
          const delay = i * 6;
          const enter = spring({
            frame: Math.max(frame - delay, 0),
            fps,
            config: { damping: 200 },
            durationInFrames: 16,
          });
          return (
            <React.Fragment key={stage.label}>
              <div
                style={{
                  opacity: enter,
                  transform: `translateY(${interpolate(enter, [0, 1], [18, 0])}px)`,
                  width: 230,
                  padding: "22px 16px",
                  textAlign: "center",
                  background: theme.panel,
                  border: `1px solid ${i === 3 ? theme.accent : theme.panelBorder}`,
                  borderRadius: 14,
                  boxShadow: i === 3 ? `0 0 30px rgba(57, 217, 138, 0.25)` : undefined,
                }}
              >
                <div style={{ color: theme.text, fontWeight: 700, fontSize: 24 }}>{stage.label}</div>
                <div style={{ color: theme.dim, fontFamily: theme.mono, fontSize: 15, marginTop: 6 }}>
                  {stage.sub}
                </div>
              </div>
              {i < STAGES.length - 1 && (
                <div
                  style={{
                    opacity: enter,
                    color: theme.accent2,
                    fontSize: 28,
                    width: 46,
                    textAlign: "center",
                  }}
                >
                  →
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>

      <Caption text={scene.caption[lang]} lang={lang} />
    </AbsoluteFill>
  );
};

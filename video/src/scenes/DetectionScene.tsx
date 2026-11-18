import React from "react";
import { AbsoluteFill, interpolate } from "remotion";
import { theme } from "../theme";
import { Panel, Dot } from "../components/Panel";
import { useEnter } from "../components/useEnter";
import { Caption } from "../components/Caption";
import type { Scene } from "../script";
import type { Lang } from "../Video";

const JSON_ROWS: [string, string][] = [
  ["rule_id", '"ssh_bruteforce"'],
  ["source_ip", '"198.51.100.23"'],
  ["failed_attempts", "8"],
  ["threshold", "5"],
  ["window_seconds", "300"],
  ["severity", '"high"'],
  ["risk_score", "40"],
];

export const DetectionScene: React.FC<{ scene: Scene; lang: Lang }> = ({ scene, lang }) => {
  const left = useEnter(0);
  const right = useEnter(14);

  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center" }}>
      <div style={{ display: "flex", gap: 36 }}>
        <Panel
          style={{
            width: 560,
            padding: 26,
            opacity: left,
            transform: `translateX(${interpolate(left, [0, 1], [-24, 0])}px)`,
          }}
        >
          <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
            <Dot color={theme.danger} />
            <Dot color={theme.warn} />
            <Dot color={theme.accent} />
            <span style={{ marginLeft: 8, color: theme.dim, fontFamily: theme.mono, fontSize: 15 }}>
              auth.log — 8 lines, 1 source
            </span>
          </div>
          <div style={{ fontFamily: theme.mono, fontSize: 18, color: "#c9d4e0", lineHeight: 2 }}>
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i}>
                <span style={{ color: theme.danger }}>Failed</span> password for user{i + 1} from{" "}
                <span style={{ color: theme.accent2 }}>198.51.100.23</span>
              </div>
            ))}
          </div>
        </Panel>

        <Panel
          style={{
            width: 460,
            padding: 26,
            opacity: right,
            transform: `translateX(${interpolate(right, [0, 1], [24, 0])}px)`,
            border: `1px solid ${theme.accent}`,
          }}
        >
          <div style={{ color: theme.accent, fontFamily: theme.mono, fontSize: 16, marginBottom: 14 }}>
            ssh_bruteforce_detected
          </div>
          <div style={{ fontFamily: theme.mono, fontSize: 19, lineHeight: 2 }}>
            {JSON_ROWS.map(([key, value]) => (
              <div key={key} style={{ display: "flex", justifyContent: "space-between" }}>
                <span style={{ color: theme.dim }}>{key}</span>
                <span style={{ color: theme.text }}>{value}</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <Caption text={scene.caption[lang]} lang={lang} />
    </AbsoluteFill>
  );
};

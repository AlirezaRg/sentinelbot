import React from "react";
import { AbsoluteFill, interpolate } from "remotion";
import { theme } from "../theme";
import { Panel } from "../components/Panel";
import { useEnter } from "../components/useEnter";
import { Caption } from "../components/Caption";
import type { Scene } from "../script";
import type { Lang } from "../Video";

const FACTORS: [string, number, string][] = [
  ["base: root_login", 35, theme.accent2],
  ["combination (+ssh_bruteforce)", 10, theme.warn],
  ["privilege (root)", 15, theme.danger],
];

export const CorrelationScene: React.FC<{ scene: Scene; lang: Lang }> = ({ scene, lang }) => {
  const card = useEnter(0);
  const bars = useEnter(16);

  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center" }}>
      <Panel
        style={{
          width: 1100,
          padding: 36,
          opacity: card,
          transform: `translateY(${interpolate(card, [0, 1], [20, 0])}px)`,
          border: `1px solid ${theme.accent}`,
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
          <div>
            <div style={{ color: theme.dim, fontFamily: theme.mono, fontSize: 16 }}>INC-7f21a9c38b4e</div>
            <div style={{ color: theme.text, fontSize: 30, fontWeight: 700, marginTop: 4 }}>
              Possible SSH brute-force activity from 198.51.100.23
            </div>
          </div>
          <div style={{ textAlign: "right" }}>
            <div style={{ color: theme.dim, fontSize: 14, fontFamily: theme.mono }}>risk score</div>
            <div style={{ color: theme.accent, fontSize: 52, fontWeight: 800 }}>60</div>
          </div>
        </div>

        <div
          style={{
            display: "flex",
            gap: 10,
            marginTop: 18,
            fontFamily: theme.mono,
            fontSize: 15,
            color: theme.dim,
          }}
        >
          <span
            style={{
              padding: "4px 12px",
              borderRadius: 999,
              border: `1px solid ${theme.panelBorder}`,
            }}
          >
            severity: high
          </span>
          <span
            style={{
              padding: "4px 12px",
              borderRadius: 999,
              border: `1px solid ${theme.panelBorder}`,
            }}
          >
            rules: ssh_bruteforce, root_login
          </span>
          <span
            style={{
              padding: "4px 12px",
              borderRadius: 999,
              border: `1px solid ${theme.panelBorder}`,
            }}
          >
            detections: 2
          </span>
        </div>

        <div style={{ marginTop: 28 }}>
          {FACTORS.map(([label, value, color], i) => {
            const localEnter = interpolate(bars, [0, 1], [0, 1]);
            const widthPct = (value / 60) * 100 * localEnter;
            return (
              <div key={label} style={{ marginBottom: 14 }}>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    fontFamily: theme.mono,
                    fontSize: 16,
                    color: theme.text,
                    marginBottom: 4,
                  }}
                >
                  <span>{label}</span>
                  <span>+{value}</span>
                </div>
                <div style={{ height: 10, background: "#121c2b", borderRadius: 6, overflow: "hidden" }}>
                  <div
                    style={{
                      height: "100%",
                      width: `${widthPct}%`,
                      background: color,
                      borderRadius: 6,
                      transitionDelay: `${i * 0.1}s`,
                    }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </Panel>

      <Caption text={scene.caption[lang]} lang={lang} />
    </AbsoluteFill>
  );
};

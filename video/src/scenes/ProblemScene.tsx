import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame } from "remotion";
import { theme } from "../theme";
import { Panel, Dot } from "../components/Panel";
import { Caption } from "../components/Caption";
import type { Scene } from "../script";
import type { Lang } from "../Video";

const LOG_LINES = [
  "Oct  5 09:12:01 host sshd[1201]: Failed password for admin from 198.51.100.23 port 40011",
  "Oct  5 09:12:04 host sshd[1201]: Failed password for root from 198.51.100.23 port 40012",
  "Oct  5 09:12:07 host sshd[1201]: Failed password for admin from 198.51.100.23 port 40013",
  "Oct  5 09:12:10 host sshd[1201]: Failed password for test from 198.51.100.23 port 40014",
  "Oct  5 09:12:13 host sshd[1201]: Failed password for admin from 198.51.100.23 port 40015",
  "Oct  5 09:12:17 host sshd[1201]: Accepted publickey for alice from 192.0.2.10 port 50201",
  "Oct  5 09:12:21 host sshd[1201]: Failed password for admin from 198.51.100.23 port 40016",
  "Oct  5 09:12:24 host sudo: alice : TTY=pts/0 ; COMMAND=/usr/bin/systemctl status nginx",
];

const LINES_PER_SECOND = 2.4;

export const ProblemScene: React.FC<{ scene: Scene; lang: Lang }> = ({ scene, lang }) => {
  const frame = useCurrentFrame();
  const fps = 30;
  const visibleLines = Math.min(LOG_LINES.length, Math.floor((frame / fps) * LINES_PER_SECOND));

  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center" }}>
      <Panel style={{ width: 1400, padding: "28px 32px" }}>
        <div style={{ display: "flex", gap: 8, marginBottom: 18 }}>
          <Dot color={theme.danger} />
          <Dot color={theme.warn} />
          <Dot color={theme.accent} />
          <span style={{ marginLeft: 8, color: theme.dim, fontFamily: theme.mono, fontSize: 16 }}>
            /var/log/auth.log
          </span>
        </div>
        <div style={{ fontFamily: theme.mono, fontSize: 21, lineHeight: 1.9 }}>
          {LOG_LINES.slice(0, visibleLines).map((line, i) => {
            const isNoise = !line.includes("Failed password");
            return (
              <div
                key={i}
                style={{
                  color: isNoise ? theme.dim : "#c9d4e0",
                  opacity: interpolate(
                    Math.min(frame - (i * fps) / LINES_PER_SECOND, fps * 0.3),
                    [0, fps * 0.3],
                    [0, 1],
                    { extrapolateLeft: "clamp", extrapolateRight: "clamp" },
                  ),
                  whiteSpace: "pre",
                }}
              >
                {line}
              </div>
            );
          })}
        </div>
      </Panel>

      <Caption text={scene.caption[lang]} lang={lang} />
    </AbsoluteFill>
  );
};

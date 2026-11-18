import React from "react";
import { AbsoluteFill, staticFile } from "remotion";
import { Audio } from "@remotion/media";
import { TransitionSeries, linearTiming } from "@remotion/transitions";
import { fade } from "@remotion/transitions/fade";
import { theme } from "./theme";
import { script, type Scene } from "./script";
import { TitleScene } from "./scenes/TitleScene";
import { ProblemScene } from "./scenes/ProblemScene";
import { ArchitectureScene } from "./scenes/ArchitectureScene";
import { DetectionScene } from "./scenes/DetectionScene";
import { CorrelationScene } from "./scenes/CorrelationScene";
import { AiScene } from "./scenes/AiScene";
import { EvaluationScene } from "./scenes/EvaluationScene";
import { ClosingScene } from "./scenes/ClosingScene";

export type Lang = "en" | "fa";

export type VideoProps = {
  lang: Lang;
  // One frame count per scene, in script order. Computed from each scene's
  // recorded narration length by calculateMetadata in Root.tsx.
  sceneFrames: number[];
};

export const TRANSITION_FRAMES = 15;

type SceneComponent = React.FC<{ scene: Scene; lang: Lang }>;

const SCENE_COMPONENTS: Record<Scene["key"], SceneComponent> = {
  title: TitleScene,
  problem: ProblemScene,
  architecture: ArchitectureScene,
  detection: DetectionScene,
  correlation: CorrelationScene,
  ai: AiScene,
  evaluation: EvaluationScene,
  closing: ClosingScene,
};

export const Video: React.FC<VideoProps> = ({ lang, sceneFrames }) => {
  return (
    <AbsoluteFill style={{ background: theme.bgGrad, fontFamily: theme.sans }}>
      <TransitionSeries>
        {script.scenes.map((scene, index) => {
          const Component = SCENE_COMPONENTS[scene.key];
          const durationInFrames = sceneFrames[index] ?? 120;
          const isLast = index === script.scenes.length - 1;

          return (
            <React.Fragment key={scene.id}>
              <TransitionSeries.Sequence durationInFrames={durationInFrames}>
                <AbsoluteFill>
                  <Audio src={staticFile(`audio/${lang}/scene-${scene.id}.mp3`)} />
                  <Component scene={scene} lang={lang} />
                </AbsoluteFill>
              </TransitionSeries.Sequence>
              {!isLast && (
                <TransitionSeries.Transition
                  presentation={fade()}
                  timing={linearTiming({ durationInFrames: TRANSITION_FRAMES })}
                />
              )}
            </React.Fragment>
          );
        })}
      </TransitionSeries>
    </AbsoluteFill>
  );
};

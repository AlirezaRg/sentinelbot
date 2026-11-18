import React from "react";
import { Composition, Folder, type CalculateMetadataFunction } from "remotion";
import { Video, TRANSITION_FRAMES, type VideoProps, type Lang } from "./Video";
import { getSceneDurationsInFrames } from "./durations";
import { script } from "./script";

const FPS = 30;
const WIDTH = 1920;
const HEIGHT = 1080;

// Shown before the real audio durations are known (first Studio load). Each
// composition's calculateMetadata overrides this with the real, audio-derived
// length as soon as it can read the files in public/audio/<lang>/.
const PLACEHOLDER_FRAMES = script.scenes.map(() => 150);
const placeholderTotal =
  PLACEHOLDER_FRAMES.reduce((sum, frames) => sum + frames, 0) -
  (PLACEHOLDER_FRAMES.length - 1) * TRANSITION_FRAMES;

const makeCalculateMetadata = (
  lang: Lang,
): CalculateMetadataFunction<VideoProps> => {
  return async () => {
    const sceneFrames = await getSceneDurationsInFrames(lang, FPS);
    const total =
      sceneFrames.reduce((sum, frames) => sum + frames, 0) -
      (sceneFrames.length - 1) * TRANSITION_FRAMES;
    return {
      durationInFrames: Math.max(total, FPS),
      props: { lang, sceneFrames },
    };
  };
};

export const RemotionRoot: React.FC = () => {
  return (
    <Folder name="SentinelBot">
      <Composition
        id="SentinelBotEN"
        component={Video}
        fps={FPS}
        width={WIDTH}
        height={HEIGHT}
        durationInFrames={placeholderTotal}
        defaultProps={{ lang: "en", sceneFrames: PLACEHOLDER_FRAMES } satisfies VideoProps}
        calculateMetadata={makeCalculateMetadata("en")}
      />
      <Composition
        id="SentinelBotFA"
        component={Video}
        fps={FPS}
        width={WIDTH}
        height={HEIGHT}
        durationInFrames={placeholderTotal}
        defaultProps={{ lang: "fa", sceneFrames: PLACEHOLDER_FRAMES } satisfies VideoProps}
        calculateMetadata={makeCalculateMetadata("fa")}
      />
    </Folder>
  );
};

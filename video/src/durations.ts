import { staticFile } from "remotion";
import { ALL_FORMATS, Input, UrlSource } from "mediabunny";
import { script } from "./script";
import type { Lang } from "./Video";

// Extra time around each clip so a scene doesn't cut the instant speech stops.
const HEAD_PAD_SECONDS = 0.4;
const TAIL_PAD_SECONDS = 0.7;
// Falls back to this length (in seconds) when a recording is missing, so the
// project still renders something playable before every clip is recorded.
const PLACEHOLDER_SECONDS = 4;

export const getAudioDurationSeconds = async (src: string): Promise<number> => {
  const input = new Input({
    formats: ALL_FORMATS,
    source: new UrlSource(src, { getRetryDelay: () => null }),
  });
  return input.computeDuration();
};

export const getSceneDurationsInFrames = async (
  lang: Lang,
  fps: number,
): Promise<number[]> => {
  const durations = await Promise.all(
    script.scenes.map(async (scene) => {
      const src = staticFile(`audio/${lang}/scene-${scene.id}.mp3`);
      let seconds = PLACEHOLDER_SECONDS;
      try {
        seconds = await getAudioDurationSeconds(src);
      } catch {
        // Recording not made yet (or the file is silent/corrupt). Use the
        // placeholder length so the Studio preview and test renders still work.
      }
      const padded = seconds + HEAD_PAD_SECONDS + TAIL_PAD_SECONDS;
      return Math.ceil(padded * fps);
    }),
  );
  return durations;
};

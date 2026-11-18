import { spring, useCurrentFrame, useVideoConfig } from "remotion";

// A standard "fade and rise in" value (0 to 1), optionally delayed by `delay` frames.
export const useEnter = (delay = 0): number => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  return spring({
    frame: Math.max(frame - delay, 0),
    fps,
    config: { damping: 200 },
    durationInFrames: 20,
  });
};

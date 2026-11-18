import { Config } from "@remotion/cli/config";

Config.setVideoImageFormat("jpeg");
Config.setOverwriteOutput(true);

// This machine's sandbox cannot download Remotion's bundled headless Chrome
// (large binary, connection reset). Use the already-installed Chrome instead.
// If this path does not exist on your machine, delete this line and Remotion
// will download its own browser on first render.
Config.setBrowserExecutable("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe");

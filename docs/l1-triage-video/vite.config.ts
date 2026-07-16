import {defineConfig} from 'vite';
import motionCanvasPlugin from '@motion-canvas/vite-plugin';
import ffmpegPlugin from '@motion-canvas/ffmpeg';

// These plugins are published as CJS; when Vite loads this config as ESM the
// real factory ends up on `.default`. Unwrap defensively so it works whatever
// interop shape the installed version uses.
const motionCanvas = (motionCanvasPlugin as any).default ?? motionCanvasPlugin;
const ffmpeg = (ffmpegPlugin as any).default ?? ffmpegPlugin;

export default defineConfig({
  plugins: [
    // Each project = one independent video. The editor shows a project
    // switcher (top-left); pick one and Render to get its .mp4 in ./output.
    motionCanvas({
      project: [
        './src/fp.project.ts',
        './src/tp.project.ts',
        './src/deepdive.project.ts',
        './src/prodarch.project.ts',
      ],
    }),
    ffmpeg(),
  ],
});

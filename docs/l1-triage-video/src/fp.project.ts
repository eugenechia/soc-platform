import {makeProject} from '@motion-canvas/core';

import fp from './scenes/fp?scene';

// False-Positive video. Pick this project in the editor's project switcher,
// then Render to produce the FP .mp4.
export default makeProject({
  scenes: [fp],
});

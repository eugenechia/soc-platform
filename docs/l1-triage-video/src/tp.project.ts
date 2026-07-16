import {makeProject} from '@motion-canvas/core';

import tp from './scenes/tp?scene';

// True-Positive video. Pick this project in the editor's project switcher,
// then Render to produce the TP .mp4.
export default makeProject({
  scenes: [tp],
});

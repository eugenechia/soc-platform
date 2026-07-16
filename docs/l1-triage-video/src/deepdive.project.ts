import {makeProject} from '@motion-canvas/core';

import infra from './scenes/infra?scene';
import workflow from './scenes/workflow?scene';
import guardrails from './scenes/guardrails?scene';

// Deep-dive video: Act 1 infrastructure, Act 2 full ticket workflow,
// Act 3 AI guardrails — rendered as one continuous MP4.
export default makeProject({
  scenes: [infra, workflow, guardrails],
});

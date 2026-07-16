import {makeProject} from '@motion-canvas/core';

import prodtopo from './scenes/prodtopo?scene';
import proddoors from './scenes/proddoors?scene';
import prodpromote from './scenes/prodpromote?scene';

// Prod private-tenant architecture explainer: Act 1 two tenants / one
// codebase, Act 2 inbound doors + controlled egress (Tavily), Act 3 the
// promote-only release workflow — rendered as one continuous MP4.
export default makeProject({
  scenes: [prodtopo, proddoors, prodpromote],
});

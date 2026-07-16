import {makeScene2D, Rect, Txt, Line, Node} from '@motion-canvas/2d';
import {all, waitFor, easeOutCubic, easeOutBack} from '@motion-canvas/core';
import {C, FONT} from '../lib/walkthrough';

/**
 * Prod Architecture · Act 3 — Promote-only releases.
 *
 * A five-step release pipeline revealed left to right (tag → build → handoff →
 * import → deploy), a rollback lane beneath it, then three boundary rules,
 * closing on the design thesis: iterate in dev, promote artifacts to prod.
 *
 * Facts verified against docs/PROD-PRIVATE-TENANT-ARCHITECTURE.md.
 */

interface Step {
  title: string;
  sub: string;
  accent: string;
  callout: string;
}

const STEPS: Step[] = [
  {title: '1 · Tag the release', sub: 'merge to main · git tag vX.Y.Z', accent: C.azure,
    callout: 'A release starts in the workflow that already exists today: the change is proven on dev — probe tickets and all — merged to main, and tagged. The tag is the release’s name everywhere from here on.'},
  {title: '2 · Build immutable image', sub: 'dev ACR · soc-platform:vX.Y.Z + digest', accent: C.azure,
    callout: 'The image is built once, into the dev registry, and the release notes record its tag AND digest — plus any env-var deltas and new secret names since the last release. That exact byte-for-byte artifact is what production will run.'},
  {title: '3 · Hand off to ops', sub: 'release notes · Bicep · runbook · scoped pull token', accent: C.intel,
    callout: 'The handoff is a package, not a login: release notes, infrastructure-as-code deltas, the runbook, and a short-lived scoped token that lets ops pull from the dev registry. Nothing more crosses the boundary.'},
  {title: '4 · Import into prod ACR', sub: 'az acr import — control-plane operation', accent: C.intel,
    callout: 'Ops imports the tag into the production registry with a single control-plane command. It works even though the prod registry is network-restricted — no tarballs, no laptops touching prod, and the tag is immutable once imported.'},
  {title: '5 · Deploy + smoke test', sub: 'containerapp update · /healthz · probe ticket', accent: C.good,
    callout: 'Ops applies the IaC deltas, points the Container App at the new tag, and smoke-tests from inside the network: /healthz first, then one probe ticket through the full triage pipeline. Done.'},
];

interface Rule {
  title: string;
  sub: string;
  accent: string;
  callout: string;
}

const RULES: Rule[] = [
  {title: 'No prod secrets on the dev side', accent: C.bad,
    sub: 'Eugene ships secret NAMES · ops enters every value',
    callout: 'The secret-name contract is one-directional: dev documents which secrets the app resolves; ops mints and enters every production value. A compromised dev machine cannot leak what it never held.'},
  {title: 'Non-overlapping Jira allowlists', accent: C.bad,
    sub: 'dev and prod must never own the same project key',
    callout: 'Both instances talk to the same Jira Cloud, so the enrichment allowlists must never share a project key — otherwise two apps triage the same ticket, twice. The allowlist fails CLOSED, so a lost variable denies everything rather than opening the door.'},
  {title: 'Automation comes later, gated', accent: C.intel,
    sub: 'GitHub Actions + OIDC + ops-owned approval — when cadence justifies it',
    callout: 'When release cadence justifies it, steps four and five become a GitHub Actions workflow federated into the prod tenant — behind an approval gate the OPS team owns. The runbook is the contract either way; automation just executes it faster.'},
];

export default makeScene2D(function* (view) {
  view.add(new Rect({width: 1920, height: 1080, fill: C.bg}));

  // ------------------------------------------------------------- act intro
  const intro = new Node({});
  intro.add(new Txt({
    text: 'Act 3 of 3 — Promote-Only Releases', y: -50,
    fontFamily: FONT, fontSize: 58, fontWeight: 700, fill: C.text, opacity: 0,
  }));
  intro.add(new Txt({
    text: 'How code crosses the tenant boundary without anyone touching prod',
    y: 30, fontFamily: FONT, fontSize: 30, fill: C.sub, opacity: 0,
  }));
  view.add(intro);
  yield* all(...intro.children().map(t => (t as Txt).opacity(1, 0.7)));
  yield* waitFor(2.6);
  yield* intro.opacity(0, 0.6);

  // ------------------------------------------------------------- scaffold
  const title = new Txt({
    text: 'Act 3 — Promote-Only Releases', x: -905, y: -510, offset: [-1, 0],
    fontFamily: FONT, fontSize: 40, fontWeight: 700, fill: C.text, opacity: 0,
  });
  view.add(title);

  const stage = new Node({});
  view.add(stage);

  const callout = new Node({y: 442, opacity: 0});
  const pill = new Rect({
    width: 1720, height: 118, radius: 30, fill: C.pill, stroke: C.ai,
    lineWidth: 2.5, shadowColor: '#00000088', shadowBlur: 20, shadowOffsetY: 6,
  });
  const pillTxt = new Txt({
    text: '', fontFamily: FONT, fontSize: 25, fontWeight: 500, fill: C.text,
    width: 1640, textAlign: 'center', textWrap: true, lineHeight: 33,
  });
  callout.add(pill);
  callout.add(pillTxt);
  view.add(callout);

  // ------------------------------------------------------------- step cards
  const SW = 330;
  const SH = 130;
  const stepX = (i: number) => -720 + i * 360;
  const stepCards: Rect[] = [];
  const stepArrows: Line[] = [];
  STEPS.forEach((s, i) => {
    if (i > 0) {
      const line = new Line({
        points: [[stepX(i - 1) + SW / 2, -280], [stepX(i) - SW / 2, -280]],
        stroke: C.link, lineWidth: 3, endArrow: true, arrowSize: 12,
        lineCap: 'round', end: 0, opacity: 0.9,
      });
      stage.add(line);
      stepArrows.push(line);
    }
    const card = new Rect({
      x: stepX(i), y: -280, width: SW, height: SH, radius: 14,
      fill: C.card, stroke: s.accent, lineWidth: 2.5,
      opacity: 0, scale: 0.92,
      shadowColor: '#00000077', shadowBlur: 18, shadowOffsetY: 6,
    });
    card.add(new Txt({
      text: s.title, y: -24, fontFamily: FONT, fontSize: 24, fontWeight: 650,
      fill: C.text, width: SW - 36, textWrap: true, textAlign: 'center', lineHeight: 29,
    }));
    card.add(new Txt({
      text: s.sub, y: 30, fontFamily: FONT, fontSize: 18, fill: C.sub,
      width: SW - 36, textWrap: true, textAlign: 'center', lineHeight: 23,
    }));
    stage.add(card);
    stepCards.push(card);
  });

  // ownership underlines: steps 1-2 Eugene (dev), 4-5 ops (prod)
  const devSpan = new Txt({
    text: '◂ Eugene · dev tenant', x: stepX(0) + 180, y: -178,
    fontFamily: FONT, fontSize: 21, fontWeight: 600, fill: C.azure, opacity: 0,
  });
  const opsSpan = new Txt({
    text: 'ops team · prod tenant ▸', x: stepX(4) - 180, y: -178,
    fontFamily: FONT, fontSize: 21, fontWeight: 600, fill: C.good, opacity: 0,
  });
  stage.add(devSpan);
  stage.add(opsSpan);

  // rollback lane
  const rbLine = new Line({
    points: [[stepX(4), -215], [stepX(4), -110], [stepX(1), -110], [stepX(1), -215]],
    stroke: C.bad, lineWidth: 3, endArrow: true, arrowSize: 12,
    lineCap: 'round', radius: 16, end: 0, lineDash: [12, 9], opacity: 0.9,
  });
  const rbLabel = new Txt({
    text: 'rollback = re-point to the previous immutable tag',
    x: (stepX(1) + stepX(4)) / 2, y: -78,
    fontFamily: FONT, fontSize: 22, fontWeight: 600, fill: C.bad, opacity: 0,
  });
  stage.add(rbLine);
  stage.add(rbLabel);

  // rule cards
  const RW = 560;
  const ruleCards: Rect[] = RULES.map((r, i) => {
    const card = new Rect({
      x: -610 + i * 610, y: 130, width: RW, height: 150, radius: 14,
      fill: C.card, stroke: r.accent, lineWidth: 2.5,
      opacity: 0, scale: 0.92,
      shadowColor: '#00000077', shadowBlur: 18, shadowOffsetY: 6,
    });
    card.add(new Txt({
      text: r.title, y: -30, fontFamily: FONT, fontSize: 25, fontWeight: 650,
      fill: C.text, width: RW - 44, textWrap: true, textAlign: 'center', lineHeight: 30,
    }));
    card.add(new Txt({
      text: r.sub, y: 30, fontFamily: FONT, fontSize: 19, fill: C.sub,
      width: RW - 44, textWrap: true, textAlign: 'center', lineHeight: 24,
    }));
    stage.add(card);
    return card;
  });

  yield* title.opacity(1, 0.5);

  // ------------------------------------------------------------- steps reveal
  for (let i = 0; i < STEPS.length; i++) {
    const s = STEPS[i];
    pillTxt.text(s.callout);
    pill.stroke(s.accent);
    if (i > 0) yield* stepArrows[i - 1].end(1, 0.26, easeOutCubic);
    yield* all(
      stepCards[i].opacity(1, 0.34),
      stepCards[i].scale(1, 0.36, easeOutBack),
      callout.opacity(1, 0.3),
    );
    if (i === 1) yield* devSpan.opacity(1, 0.3);
    if (i === 4) yield* opsSpan.opacity(1, 0.3);
    yield* waitFor(Math.max(3.4, s.callout.length * 0.028));
    yield* callout.opacity(0, 0.22);
  }

  // ------------------------------------------------------------- rollback
  pillTxt.text('Rollback keeps the discipline the dev tenant already uses: every release is an immutable tag, so recovery is re-pointing the app at the previous one. No rebuilds under pressure.');
  pill.stroke(C.bad);
  yield* all(rbLine.end(1, 0.7, easeOutCubic), callout.opacity(1, 0.3));
  yield* rbLabel.opacity(1, 0.3);
  yield* waitFor(4.8);
  yield* callout.opacity(0, 0.22);

  // ------------------------------------------------------------- boundary rules
  for (let i = 0; i < RULES.length; i++) {
    const r = RULES[i];
    pillTxt.text(r.callout);
    pill.stroke(r.accent);
    yield* all(
      ruleCards[i].opacity(1, 0.34),
      ruleCards[i].scale(1, 0.36, easeOutBack),
      callout.opacity(1, 0.3),
    );
    yield* waitFor(Math.max(4.0, r.callout.length * 0.026));
    yield* callout.opacity(0, 0.22);
  }

  // ------------------------------------------------------------- closing
  yield* waitFor(0.3);
  yield* all(stage.opacity(0.14, 0.8), title.opacity(0, 0.6));

  const thesis = new Node({});
  thesis.add(new Txt({
    text: 'Iterate in dev. Promote artifacts. Never touch prod.', y: -80,
    fontFamily: FONT, fontSize: 54, fontWeight: 700, fill: C.text, opacity: 0,
  }));
  thesis.add(new Txt({
    text: 'The production tenant stays private because nothing interactive ever crosses into it: analysts arrive over the corporate network, Jira through one path-locked door, data leaves only past a default-deny firewall — and code arrives only as an immutable, tested, ops-imported image.',
    y: 40, fontFamily: FONT, fontSize: 27, fill: C.sub, opacity: 0,
    width: 1500, textWrap: true, textAlign: 'center', lineHeight: 40,
  }));
  thesis.add(new Txt({
    text: 'no public FQDN · five private endpoints · one allowlisted gate out · promote-only releases',
    y: 175, fontFamily: FONT, fontSize: 23, fill: C.good, opacity: 0,
  }));
  view.add(thesis);
  yield* all(...thesis.children().map(t => (t as Txt).opacity(1, 0.9)));
  yield* waitFor(6.5);
  yield* all(thesis.opacity(0, 0.8), stage.opacity(0, 0.8));
  yield* waitFor(0.5);
});

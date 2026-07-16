import {Rect, Txt, Line, Node, Img, View2D} from '@motion-canvas/2d';
import {
  all,
  waitFor,
  easeInOutCubic,
  easeOutCubic,
  easeOutBack,
} from '@motion-canvas/core';

/**
 * Shared engine for the L1 Triage scenario videos.
 *
 * Every scenario (False-Positive, True-Positive, ...) is the SAME video:
 *   Act 1  abstract upstream flow (Source -> Sentinel -> Logic Apps -> Jira
 *          -> L1 service) — identical across scenarios, built here.
 *   Act 2  spotlight walkthrough of that scenario's real comment — the page
 *          freezes (dims) and each component lights up in a highlight box with
 *          a callout.
 *
 * A scene file just calls runScenario(view, config) and supplies its own
 * screenshots + region map. No animation logic lives in the scene files.
 */

export const C = {
  bg: '#0b1221',
  card: '#16243b',
  text: '#e8eef7',
  sub: '#93a6c4',
  link: '#5a6f90',
  azure: '#38bdf8',
  jira: '#5b8def',
  ai: '#c084fc',
  intel: '#f5b53d',
  good: '#34d399',
  bad: '#f87171',
  pill: '#0e1830',
};
export const FONT = 'Inter, "Segoe UI", system-ui, sans-serif';

/** A stacked screenshot: its source URL and natural pixel size. */
export interface ScenarioImage {
  src: string;
  w: number;
  h: number;
}

/**
 * One spotlight. `img` indexes into config.images; `x,y` is the region CENTRE
 * in that image's own pixel coordinates; `w,h` the region size; `hold` seconds.
 */
export interface Section {
  label: string;
  accent: string;
  img: number;
  x: number;
  y: number;
  w: number;
  h: number;
  hold: number;
}

export interface ScenarioConfig {
  /** Act 2 heading, e.g. 'L1 Triage enrichment comment · SCDM-649'. */
  title: string;
  /** Act 2 sub-heading. */
  sub: string;
  /** Sub-heading swapped in during the closing reveal. */
  closingSub: string;
  /** Screenshots, top to bottom, treated as one continuous document. */
  images: ScenarioImage[];
  /** Spotlights, in the order they should play. */
  sections: Section[];
  /** Gap (px) inserted between stacked screenshots. Default 40. */
  gap?: number;
  /** Global speed multiplier. Default 1 (raise to slow down for narration). */
  pace?: number;
}

const A1_STAGES = [
  {id: 'src', title: 'Source', accent: C.sub,
    desc: 'Suspicious activity originates in the customer environment'},
  {id: 'siem', title: 'SIEM', accent: C.azure, from: 'src',
    desc: 'An analytics rule fires and raises an incident'},
  {id: 'incident', title: 'Incident Triggered', accent: C.jira, from: 'siem',
    desc: 'Automation opens the Jira ticket and hands it to the agent'},
  {id: 'agent', title: 'L1 Triage Agent', accent: C.ai, from: 'incident',
    desc: 'Objective — determine whether the incident is a true or false positive'},
  {id: 'review', title: 'Human Review', accent: C.intel, from: 'agent',
    desc: 'Analyst validates the AI verdict and enrichment'},
  {id: 'action', title: 'Perform Next Action', accent: C.good, from: 'review',
    desc: 'Close, escalate, or remediate based on the outcome'},
];

export function* runScenario(view: View2D, config: ScenarioConfig) {
  const PACE = config.pace ?? 1;
  const GAP2 = config.gap ?? 40;

  view.add(new Rect({width: 1920, height: 1080, fill: C.bg}));

  // ====================================================================
  //  ACT 1 — upstream flow
  // ====================================================================
  const SX = -220;
  const W = 380;
  const H = 96;
  const VSTEP = 196;

  const cam = new Node({position: [0, -120]});
  const links = new Node({});
  const nodes = new Node({});
  cam.add(links);
  cam.add(nodes);
  view.add(cam);

  type A1 = (typeof A1_STAGES)[number] & {
    x: number; y: number; card?: Rect; callout?: Txt; arrow?: Line;
  };
  const a1: Record<string, A1> = {};
  const a1List: A1[] = A1_STAGES.map((r, i) => {
    const s: A1 = {...r, x: SX, y: i * VSTEP};
    a1[r.id] = s;
    return s;
  });

  for (const s of a1List) {
    if ('from' in s && s.from) {
      const p = a1[s.from];
      const line = new Line({
        points: [[p.x, p.y + H / 2], [s.x, s.y - H / 2]],
        stroke: C.link, lineWidth: 3, endArrow: true, arrowSize: 12,
        lineCap: 'round', end: 0, opacity: 0.95,
      });
      links.add(line);
      s.arrow = line;
    }
    const card = new Rect({
      x: s.x, y: s.y, width: W, height: H, radius: 12,
      fill: C.card, stroke: s.accent, lineWidth: 2.5, opacity: 0, scale: 0.9,
      shadowColor: '#00000077', shadowBlur: 18, shadowOffsetY: 6,
    });
    card.add(new Txt({
      text: s.title, fontFamily: FONT, fontSize: 25, fontWeight: 600,
      fill: C.text, width: W - 28, textWrap: true, textAlign: 'center',
      lineHeight: 30,
    }));
    nodes.add(card);
    s.card = card;
    const call = new Txt({
      text: s.desc, fontFamily: FONT, fontSize: 22, fill: C.sub,
      x: s.x + W / 2 + 34, y: s.y, offset: [-1, 0],
      width: 620, textWrap: true, textAlign: 'left', lineHeight: 30, opacity: 0,
    });
    nodes.add(call);
    s.callout = call;
  }

  const a1title = new Txt({
    text: 'L1 Triage — End to End', x: -905, y: -468, offset: [-1, 0],
    fontFamily: FONT, fontSize: 42, fontWeight: 700, fill: C.text, opacity: 0,
  });
  const a1sub = new Txt({
    text: 'Step 1 — the incident triage flow, end to end',
    x: -903, y: -424, offset: [-1, 0],
    fontFamily: FONT, fontSize: 22, fill: C.sub, opacity: 0,
  });
  view.add(a1title);
  view.add(a1sub);

  // ====================================================================
  //  ACT 2 — build the document + spotlights from config
  // ====================================================================
  const S2 = 0.8;
  const TOP_SCREEN = -250;

  // stack the screenshots into one document
  let cursor = 0;
  const imgTop: number[] = [];
  const imgCenter: {x: number; y: number}[] = [];
  for (const im of config.images) {
    imgTop.push(cursor);
    imgCenter.push({x: im.w / 2, y: cursor + im.h / 2});
    cursor += im.h + GAP2;
  }
  const totalH = cursor - GAP2;
  const docCx = Math.max(...config.images.map(im => im.w)) / 2;

  const doc = new Node({position: [-docCx * S2, 0], scale: S2, opacity: 0});
  view.add(doc);
  config.images.forEach((im, i) => {
    doc.add(new Img({src: im.src, width: im.w, height: im.h,
      x: imgCenter[i].x, y: imgCenter[i].y}));
  });
  const dim = new Rect({
    x: docCx, y: totalH / 2, width: docCx * 2 + 300, height: totalH + 200,
    fill: '#05080f', opacity: 0,
  });
  doc.add(dim);

  // resolve each section into doc-space + build its bright cut-out window
  type Built = Section & {sy: number; win: Rect};
  const built: Built[] = config.sections.map(sec => {
    const sy = imgTop[sec.img] + sec.y;
    const sx = sec.x;
    const im = config.images[sec.img];
    const win = new Rect({
      x: sx, y: sy, width: sec.w, height: sec.h,
      clip: true, stroke: sec.accent, lineWidth: 5, radius: 6, opacity: 0,
    });
    win.add(new Img({
      src: im.src, width: im.w, height: im.h,
      x: imgCenter[sec.img].x - sx, y: imgCenter[sec.img].y - sy,
    }));
    doc.add(win);
    return {...sec, sy, win};
  });
  const camTarget = (b: Built) => TOP_SCREEN - (b.sy - b.h / 2) * S2;

  const a2title = new Txt({
    text: config.title, x: -905, y: -468, offset: [-1, 0],
    fontFamily: FONT, fontSize: 34, fontWeight: 700, fill: C.text, opacity: 0,
  });
  const a2sub = new Txt({
    text: config.sub, x: -903, y: -428, offset: [-1, 0],
    fontFamily: FONT, fontSize: 21, fill: C.sub, opacity: 0,
  });
  view.add(a2title);
  view.add(a2sub);

  const callout = new Node({y: -312, opacity: 0});
  const pill = new Rect({
    width: 1500, height: 68, radius: 34, fill: C.pill, stroke: C.ai,
    lineWidth: 2.5, shadowColor: '#00000088', shadowBlur: 20, shadowOffsetY: 6,
  });
  const pillTxt = new Txt({
    text: '', fontFamily: FONT, fontSize: 25, fontWeight: 500, fill: C.text,
    width: 1430, textAlign: 'center', textWrap: true, lineHeight: 30,
  });
  callout.add(pill);
  callout.add(pillTxt);
  view.add(callout);

  // ====================================================================
  //  RUN
  // ====================================================================
  yield* all(a1title.opacity(1, 0.6 * PACE), a1sub.opacity(1, 0.6 * PACE));
  yield* waitFor(0.4 * PACE);

  for (const s of a1List) {
    if (s.arrow) yield* s.arrow.end(1, 0.28 * PACE, easeOutCubic);
    yield* all(
      cam.position.y(-120 - s.y, 0.5 * PACE, easeInOutCubic),
      s.card!.opacity(1, 0.34 * PACE),
      s.card!.scale(1, 0.36 * PACE, easeOutBack),
      s.callout!.opacity(1, 0.34 * PACE),
    );
    yield* waitFor(0.2 * PACE);
  }
  yield* waitFor(0.8 * PACE);

  // transition Act 1 -> Act 2
  yield* all(
    cam.opacity(0, 0.6 * PACE),
    a1title.opacity(0, 0.5 * PACE),
    a1sub.opacity(0, 0.5 * PACE),
  );
  doc.position([-docCx * S2, camTarget(built[0])]);
  yield* all(
    doc.opacity(1, 0.7 * PACE),
    a2title.opacity(1, 0.6 * PACE),
    a2sub.opacity(1, 0.6 * PACE),
  );
  yield* waitFor(0.6 * PACE);
  yield* dim.opacity(0.74, 0.5 * PACE);

  // spotlights
  for (let i = 0; i < built.length; i++) {
    const b = built[i];
    if (i > 0) {
      yield* doc.position.y(camTarget(b), 0.7 * PACE, easeInOutCubic);
    }
    pillTxt.text(b.label);
    pill.stroke(b.accent);
    yield* all(b.win.opacity(1, 0.35 * PACE), callout.opacity(1, 0.3 * PACE));
    yield* waitFor(b.hold * PACE);
    yield* all(b.win.opacity(0, 0.3 * PACE), callout.opacity(0, 0.25 * PACE));
  }

  // outro — lift the veil, reveal the whole comment, hold
  yield* all(
    dim.opacity(0, 0.6 * PACE),
    a2sub.text(config.closingSub, 0.4 * PACE),
  );
  yield* waitFor(2.4 * PACE);
}

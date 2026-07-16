// Motion Canvas resolves `*?scene` imports at build time (Vite virtual module).
// This ambient declaration keeps `tsc` happy; the real type comes from the bundler.
declare module '*?scene' {
  const scene: any;
  export default scene;
}

// Image assets imported into scenes resolve to URL strings via Vite.
declare module '*.png' {
  const src: string;
  export default src;
}

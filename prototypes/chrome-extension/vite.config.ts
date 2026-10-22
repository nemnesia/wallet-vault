import { defineConfig } from 'vite';
export default defineConfig({
  base: './',
  build: {
    assetsInlineLimit: 0,
    target: 'es2022',
    rollupOptions: { input: { prototype: 'prototype.html' } },
  },
  test: { include: ['tests/**/*.test.ts'] },
});

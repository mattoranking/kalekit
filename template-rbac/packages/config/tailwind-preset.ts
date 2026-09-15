import type { Config } from 'tailwindcss';

/**
 * Shared Tailwind preset for all Kalekit web surfaces.
 * Design tokens live here — not a component library.
 */
const preset: Omit<Config, 'content'> = {
  theme: {
    extend: {
      colors: {
        brand: {
          DEFAULT: '#1f6feb',
          fg: '#ffffff',
        },
      },
    },
  },
  plugins: [],
};

export default preset;

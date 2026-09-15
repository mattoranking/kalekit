import type { Config } from 'tailwindcss';
import preset from '@kalekit/config/tailwind-preset';

const config: Config = {
  presets: [preset],
  content: [
    './app/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
  ],
};

export default config;

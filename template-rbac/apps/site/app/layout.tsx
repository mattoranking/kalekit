import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Kalekit — on-demand property viewings in the Netherlands',
  description:
    'Relocating to the Netherlands? Send a verified Local to view a property for you and report back with photos, a live call and a written report.',
  manifest: '/manifest.json',
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}

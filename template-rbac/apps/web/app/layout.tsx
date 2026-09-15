import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Kalekit',
  description:
    'Book a verified Local to attend a property viewing in the Netherlands and report back.',
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

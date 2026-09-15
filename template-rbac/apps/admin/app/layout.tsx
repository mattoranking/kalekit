import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Kalekit Admin',
  description: 'Operations console — matching, reassignment, refunds, late reports.',
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

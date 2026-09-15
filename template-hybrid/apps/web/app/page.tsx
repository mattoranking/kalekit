import Link from 'next/link';

export default function Home() {
  return (
    <main className="mx-auto flex min-h-screen max-w-2xl flex-col justify-center gap-6 p-8">
      <h1 className="text-4xl font-bold tracking-tight">Kalekit</h1>
      <p className="text-lg text-gray-600 dark:text-gray-400">
        Can&apos;t make the viewing? Send a verified Local. They attend the
        property, walk it on a live call, take photos, and write up what they
        found.
      </p>
      <div>
        <Link
          href="/book"
          className="inline-block rounded-lg bg-brand px-6 py-3 font-medium text-brand-fg transition-colors hover:opacity-90"
        >
          Book a viewing
        </Link>
      </div>
    </main>
  );
}

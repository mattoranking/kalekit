export default function Home() {
  return (
    <main className="mx-auto flex min-h-screen max-w-3xl flex-col justify-center gap-8 p-8">
      <header className="flex flex-col gap-4">
        <h1 className="text-5xl font-bold tracking-tight">
          Viewings, handled by a Local.
        </h1>
        <p className="text-xl text-gray-600 dark:text-gray-400">
          You&apos;re abroad. The apartment is in Amsterdam. A verified Local
          attends the viewing, calls you from the doorway, and sends photos and a
          written report the same day.
        </p>
      </header>

      <section className="grid gap-6 sm:grid-cols-3">
        {[
          ['Snapshot', '€27.50', 'Photos and a written summary.'],
          ['Live View', '€47.50', 'A live video call plus photos.'],
          ['The Full View', '€77.50', 'Live call, full report, neighbourhood notes.'],
        ].map(([tier, price, blurb]) => (
          <div key={tier} className="rounded-xl border border-gray-200 p-5 dark:border-gray-800">
            <div className="text-sm font-medium text-gray-500">{tier}</div>
            <div className="mt-1 text-2xl font-bold">{price}</div>
            <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">{blurb}</p>
          </div>
        ))}
      </section>

      <div>
        <a
          href="https://app.kalekit.one"
          className="inline-block rounded-lg bg-brand px-6 py-3 font-medium text-brand-fg transition-colors hover:opacity-90"
        >
          Book a viewing
        </a>
      </div>
    </main>
  );
}

const QUEUES = [
  ['Awaiting assignment', 'Bookings paid, no Local yet — broadcast or assign by hand.'],
  ['Escalated', 'Nobody accepted within 12h. Needs an admin.'],
  ['Late reports', 'Viewing done, report overdue. Chase the Local.'],
  ['Refunds & downgrades', 'Missed calls, tier downgrades, cancellations.'],
];

export default function AdminHome() {
  return (
    <main className="mx-auto max-w-5xl p-8">
      <h1 className="text-2xl font-bold tracking-tight">Kalekit Admin</h1>
      <p className="mt-1 text-sm text-gray-500">
        For the first hundred bookings a human does the matching and fixes the
        edge cases. The admin panel is the product.
      </p>

      <div className="mt-8 grid gap-4 sm:grid-cols-2">
        {QUEUES.map(([title, blurb]) => (
          <div key={title} className="rounded-lg border border-gray-200 p-5 dark:border-gray-800">
            <div className="font-semibold">{title}</div>
            <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">{blurb}</p>
          </div>
        ))}
      </div>
    </main>
  );
}

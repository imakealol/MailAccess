export default function SkeletonCard() {
  return (
    <div className="bg-zinc-900/60 border border-zinc-800/60 rounded-sm overflow-hidden animate-pulse">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-zinc-800/40">
        <div className="h-2.5 bg-zinc-800 rounded w-28" />
        <div className="flex-1 h-px bg-zinc-800/60" />
        <div className="h-2 bg-zinc-800 rounded w-10" />
      </div>
      <div className="px-4 py-3 space-y-2.5">
        {[40, 64, 52].map(w => (
          <div key={w} className="flex gap-3">
            <div className="h-2 bg-zinc-800 rounded w-24 flex-shrink-0" />
            <div className={`h-2 bg-zinc-800/70 rounded`} style={{ width: `${w}%` }} />
          </div>
        ))}
      </div>
    </div>
  )
}

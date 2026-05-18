import { useEffect, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { api } from '../api/client'

export default function NavBar() {
  const [count, setCount] = useState<number>(0)
  const location = useLocation()

  useEffect(() => {
    api.listInvestigations(1, 1).then(r => setCount(r.total)).catch(() => {})
  }, [])

  return (
    <header className="border-b border-zinc-800 bg-zinc-900/60 px-5 py-3 flex items-center gap-4 flex-shrink-0 font-mono">
      <Link to="/" className="flex items-center gap-2 group">
        <svg width="14" height="14" viewBox="0 0 28 28" fill="none" className="opacity-50 group-hover:opacity-100 transition-opacity">
          <polygon
            points="14,2 26,8 26,20 14,26 2,20 2,8"
            stroke="#22d3ee"
            strokeWidth="1.5"
            fill="rgba(34,211,238,0.06)"
          />
        </svg>
        <span className="text-zinc-500 group-hover:text-zinc-200 text-sm transition-colors">
          MailAccess
        </span>
      </Link>

      <div className="h-4 w-px bg-zinc-800" />

      <Link
        to="/history"
        className={`flex items-center gap-2 text-sm transition-colors ${
          location.pathname === '/history'
            ? 'text-cyan-400'
            : 'text-zinc-500 hover:text-zinc-200'
        }`}
      >
        History
        {count > 0 && (
          <span className="text-xs bg-zinc-800 border border-zinc-700 text-zinc-400 px-1.5 py-0.5 rounded-sm tabular-nums leading-none">
            {count}
          </span>
        )}
      </Link>
    </header>
  )
}

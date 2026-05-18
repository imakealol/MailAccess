import { useState, useEffect } from 'react'

interface Props {
  score: number
}

function accentColor(score: number): string {
  if (score <= 20) return '#34d399' // emerald-400
  if (score <= 50) return '#facc15' // yellow-400
  if (score <= 80) return '#f97316' // orange-500
  return '#ef4444'                  // red-500
}

export default function ExposureGauge({ score }: Props) {
  // Animate from 0 on mount / on score change
  const [displayed, setDisplayed] = useState(0)

  useEffect(() => {
    const t = setTimeout(() => setDisplayed(Math.max(0, Math.min(100, score))), 120)
    return () => clearTimeout(t)
  }, [score])

  const color = accentColor(displayed)
  // pathLength="100" → dashoffset = 100 - score fills the arc
  const offset = 100 - displayed

  return (
    <svg
      viewBox="0 0 120 70"
      width="96"
      height="56"
      className="overflow-visible flex-shrink-0"
      aria-label={`Exposure score: ${score}`}
    >
      {/* Track */}
      <path
        d="M 10 65 A 50 50 0 0 1 110 65"
        fill="none"
        stroke="#27272a"
        strokeWidth="9"
        strokeLinecap="round"
      />
      {/* Glow layer */}
      <path
        d="M 10 65 A 50 50 0 0 1 110 65"
        fill="none"
        stroke={color}
        strokeWidth="9"
        strokeLinecap="round"
        pathLength="100"
        strokeDasharray="100"
        strokeDashoffset={offset}
        opacity="0.25"
        style={{
          transition: 'stroke-dashoffset 1.1s cubic-bezier(0.4,0,0.2,1), stroke 0.4s ease',
          filter: `blur(4px)`,
        }}
      />
      {/* Fill arc */}
      <path
        d="M 10 65 A 50 50 0 0 1 110 65"
        fill="none"
        stroke={color}
        strokeWidth="9"
        strokeLinecap="round"
        pathLength="100"
        strokeDasharray="100"
        strokeDashoffset={offset}
        style={{
          transition: 'stroke-dashoffset 1.1s cubic-bezier(0.4,0,0.2,1), stroke 0.4s ease',
        }}
      />
    </svg>
  )
}

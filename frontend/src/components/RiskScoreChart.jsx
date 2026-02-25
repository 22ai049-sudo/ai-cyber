import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, XAxis, YAxis } from 'recharts'

export default function RiskScoreChart({ result, live }) {
  if (!result) return null
  const confidence = Math.round(result.confidence * 100)
  const vtMal = Number(result?.virustotal?.malicious || 0)
  const abuse = Number(result?.abuseipdb?.abuse_confidence_score || 0)
  const modelScore = Math.round(Number(result?.model_validation?.score || 0) * 100)
  const data = [
    { name: 'Confidence', score: confidence },
    { name: 'VT Malicious', score: Math.min(vtMal * 10, 100) },
    { name: 'AbuseIPDB', score: abuse },
    { name: 'Model Valid', score: modelScore },
  ]
  const color =
    result.severity === 'critical' ? '#ff507f' : result.severity === 'high' ? '#ff9f43' : '#3ddc97'

  return (
    <section className='card'>
      <h3>Risk Severity: {result.severity.toUpperCase()}</h3>
      <div className='kpis'>
        <div><small>Threat Detected</small><strong>{result.confidence > 0.55 ? 'YES' : 'NO'}</strong></div>
        <div><small>Detection Score</small><strong>{confidence}%</strong></div>
        <div><small>ATAVE Verdict</small><strong>{result.severity === 'critical' ? 'Require Human Review' : 'Auto Eligible'}</strong></div>
        <div><small>Resolver Mode</small><strong>{result.sandbox_execution.length ? 'Auto' : 'Advisory'}</strong></div>
        <div><small>Model Validation</small><strong>{result?.model_validation?.status?.toUpperCase() || 'N/A'}</strong></div>
        <div><small>Validation Score</small><strong>{modelScore}%</strong></div>
        <div><small>Risk Score</small><strong>{result?.risk_score || 0}/10</strong></div>
        <div><small>Intel Score</small><strong>{abuse}% AbuseIPDB</strong></div>
      </div>
      <ResponsiveContainer width='100%' height={220}>
        <BarChart data={data}>
          <CartesianGrid strokeDasharray='3 3' stroke='#253053' />
          <XAxis dataKey='name' stroke='#9eb2d8' />
          <YAxis domain={[0, 100]} stroke='#9eb2d8' />
          <Bar dataKey='score'>
            {data.map((_, idx) => <Cell key={idx} fill={color} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
      {live && <p className='muted'>Live alerts: {live.active_alerts} | Triage backlog: {live.triage_backlog}</p>}
    </section>
  )
}

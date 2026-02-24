import { useState } from 'react'
import IncidentPanel from './IncidentPanel'
import ExplainabilityPanel from './ExplainabilityPanel'
import MitigationPanel from './MitigationPanel'
import RiskScoreChart from './RiskScoreChart'
import AuditLogsViewer from './AuditLogsViewer'
import { getAudit, login, processIncident } from '../services/api'

export default function AnalystDashboard() {
  const [token, setToken] = useState('')
  const [result, setResult] = useState(null)
  const [logs, setLogs] = useState([])
  const [form, setForm] = useState({ source: 'siem', indicator: '', message: '', execute: false })

  const loginNow = async () => setToken(await login('socadmin', 'socpass'))
  const submit = async () => {
    const out = await processIncident(token, {
      source: form.source,
      indicator: form.indicator,
      context: { message: form.message },
      execute_mitigation: form.execute,
    })
    setResult(out)
    const audit = await getAudit(token, out.incident_id)
    setLogs(audit.logs)
  }

  return (
    <div className='dashboard'>
      <header><h1>AI SOC Solver</h1><button onClick={loginNow}>{token ? 'Authenticated' : 'Authenticate'}</button></header>
      <IncidentPanel form={form} setForm={setForm} onSubmit={submit} />
      <div className='grid'>
        <RiskScoreChart result={result} />
        <ExplainabilityPanel result={result} />
        <MitigationPanel result={result} />
        <AuditLogsViewer logs={logs} />
      </div>
    </div>
  )
}

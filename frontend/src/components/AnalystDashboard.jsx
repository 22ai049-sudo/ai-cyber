import { useEffect, useState } from 'react'
import IncidentPanel from './IncidentPanel'
import ExplainabilityPanel from './ExplainabilityPanel'
import MitigationPanel from './MitigationPanel'
import RiskScoreChart from './RiskScoreChart'
import AuditLogsViewer from './AuditLogsViewer'
import {
  getAudit,
  getAutomaticIngestion,
  getIngestionSamples,
  getLiveIngestion,
  getLogSamples,
  login,
  parseSecurityLog,
  processIncident,
} from '../services/api'

export default function AnalystDashboard() {
  const [token, setToken] = useState('')
  const [result, setResult] = useState(null)
  const [logs, setLogs] = useState([])
  const [samples, setSamples] = useState([])
  const [live, setLive] = useState(null)
  const [autoFeed, setAutoFeed] = useState([])
  const [logSamples, setLogSamples] = useState({})
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [form, setForm] = useState({
    source: 'suricata',
    indicator: '10.10.4.13',
    message: 'Repeated credential brute-force attempts on SSH with lockout bursts.',
    execute: false,
    ingestion_mode: 'manual',
    dataset_name: '',
  })

  const loginNow = async () => {
    try {
      setError('')
      const authToken = await login('socadmin', 'socpass')
      setToken(authToken)
    } catch (e) {
      setError(`Authentication failed: ${e.message}`)
    }
  }

  useEffect(() => {
    if (!token) return
    const hydrate = async () => {
      try {
        const [seedSamples, liveData, autoData, logData] = await Promise.all([
          getIngestionSamples(token),
          getLiveIngestion(token),
          getAutomaticIngestion(token),
          getLogSamples(token),
        ])
        setSamples(seedSamples)
        setLive(liveData)
        setAutoFeed(autoData.indicators || [])
        setLogSamples(logData || {})
      } catch (e) {
        setError(`Failed to load ingestion feeds: ${e.message}`)
      }
    }
    hydrate()
    const interval = setInterval(async () => {
      try {
        setLive(await getLiveIngestion(token))
      } catch {
        // keep dashboard stable if polling fails intermittently
      }
    }, 12000)
    return () => clearInterval(interval)
  }, [token])

  const onLoadSample = (sample) => {
    setForm((prev) => ({
      ...prev,
      source: sample.source,
      indicator: sample.indicator,
      message: sample.message,
      ingestion_mode: 'manual',
      dataset_name: sample.dataset,
    }))
  }

  const onLoadAutomaticIndicator = (item) => {
    setForm((prev) => ({
      ...prev,
      source: `auto-feed:${item.source}`,
      indicator: item.indicator,
      message: `Automatic global ingestion: ${item.reason}`,
      ingestion_mode: 'automatic',
      dataset_name: '',
    }))
  }

  const onParseLog = async (source, rawLog) => {
    if (!token) {
      setError('Authenticate first to parse logs.')
      return
    }
    try {
      const parsed = await parseSecurityLog(token, { source, raw_log: rawLog })
      if (!parsed.parsed) {
        setError('Could not parse indicator from the selected log format.')
        return
      }
      setForm((prev) => ({
        ...prev,
        source: parsed.source,
        indicator: parsed.indicator,
        message: parsed.message,
        ingestion_mode: 'manual',
      }))
      setError('')
    } catch (e) {
      setError(`Log parsing failed: ${e.message}`)
    }
  }

  const submit = async () => {
    if (!token) {
      setError('Authenticate first to analyze incidents.')
      return
    }
    try {
      setBusy(true)
      setError('')
      const out = await processIncident(token, {
        source: form.source,
        indicator: form.indicator,
        context: { message: form.message },
        execute_mitigation: form.execute,
        ingestion_mode: form.ingestion_mode,
        dataset_name: form.dataset_name || null,
      })
      setResult(out)
      const audit = await getAudit(token, out.incident_id)
      setLogs(audit.logs)
    } catch (e) {
      setError(`Incident processing failed: ${e.message}`)
    } finally {
      setBusy(false)
    }
  }

  const canSubmit = Boolean(form.indicator.trim())

  return (
    <div className='dashboard'>
      <header className='hero card'>
        <div>
          <h1>🛡️ AI SOC Copilot Dashboard</h1>
          <p>Automatic threat detection + local LLM explainability + safe response orchestration.</p>
          <div className='tag-row'>
            <span>Auto Threat Detection</span>
            <span>LLM Analysis</span>
            <span>ATAVE Safety</span>
            <span>Auto Resolution</span>
          </div>
        </div>
        <button className='auth-btn' onClick={loginNow}>{token ? 'Authenticated ✅' : 'Authenticate'}</button>
      </header>

      {error && <div className='card error'>{error}</div>}
      <IncidentPanel
        form={form}
        setForm={setForm}
        onSubmit={submit}
        samples={samples}
        onLoadSample={onLoadSample}
        autoIndicators={autoFeed}
        onLoadAutomaticIndicator={onLoadAutomaticIndicator}
        busy={busy}
        canSubmit={canSubmit}
        logSamples={logSamples}
        onParseLog={onParseLog}
      />

      <section className='card'>
        <h3>How this solves incident handling</h3>
        <p className='muted'>
          Manual mode lets analysts submit custom events or parsed Sysmon/Suricata/Wazuh logs. Automatic mode collects corrupted/suspicious IPs from global feeds, then enriches with VirusTotal + AbuseIPDB, maps ATT&CK techniques, scores risk (CVSS-like), and validates model consistency before action.
        </p>
      </section>

      {live && (
        <section className='card'>
          <h3>Incident Feed (Live Values)</h3>
          <table className='feed-table'>
            <thead><tr><th>Time</th><th>Source</th><th>Severity</th><th>Indicator</th><th>Signal</th><th>Confidence</th></tr></thead>
            <tbody>
              {live.feed.map((item, idx) => (
                <tr key={idx}><td>{new Date(item.time).toLocaleTimeString()}</td><td>{item.source}</td><td>{item.severity}</td><td>{item.indicator}</td><td>{item.message}</td><td>{item.confidence}</td></tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      <div className='grid'>
        <RiskScoreChart result={result} live={live} />
        <MitigationPanel result={result} />
      </div>
      <ExplainabilityPanel result={result} />
      <AuditLogsViewer logs={logs} />
    </div>
  )
}

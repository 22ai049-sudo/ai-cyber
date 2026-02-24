export default function AuditLogsViewer({ logs }) {
  if (!logs?.length) return null
  return <div className='card'><h3>Sandbox & Pipeline Audit Logs</h3><ul>{logs.map((l,i)=><li key={i}><b>{l.action}</b> [{l.ts}]</li>)}</ul></div>
}

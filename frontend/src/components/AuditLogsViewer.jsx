export default function AuditLogsViewer({ logs }) {
  if (!logs?.length) return null
  return (
    <section className='card'>
      <h3>Pipeline Audit Trail</h3>
      <div className='audit-list'>
        {logs.map((item, idx) => (
          <div key={idx} className='audit-row'>
            <strong>{item.action}</strong>
            <span>{new Date(item.ts).toLocaleString()}</span>
          </div>
        ))}
      </div>
    </section>
  )
}

export default function IncidentPanel({ form, setForm, onSubmit }) {
  return (
    <div className='card'>
      <h3>Incident Ingestion</h3>
      <input placeholder='Source (siem/edr)' value={form.source} onChange={(e)=>setForm({...form, source:e.target.value})} />
      <input placeholder='Indicator (IP/hash/domain)' value={form.indicator} onChange={(e)=>setForm({...form, indicator:e.target.value})} />
      <textarea placeholder='Analyst context / log excerpt' value={form.message} onChange={(e)=>setForm({...form, message:e.target.value})} />
      <label><input type='checkbox' checked={form.execute} onChange={(e)=>setForm({...form, execute:e.target.checked})} /> Execute approved commands in sandbox</label>
      <button onClick={onSubmit}>Analyze & Orchestrate</button>
    </div>
  )
}

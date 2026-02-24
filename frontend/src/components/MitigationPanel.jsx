export default function MitigationPanel({ result }) {
  if (!result) return null
  return (
    <div className='card'>
      <h3>Mitigation Plan</h3>
      <ul>{result.mitigation.playbook.map((s,i)=><li key={i}>{s}</li>)}</ul>
      <h4>Commands</h4>
      <ul>{result.mitigation.commands.map((c,i)=><li key={i}><code>{c}</code> - {result.command_validation[i]?.reason}</li>)}</ul>
    </div>
  )
}

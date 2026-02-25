export default function MitigationPanel({ result }) {
  if (!result) return null

  return (
    <section className='card'>
      <h3>Mitigation Playbook</h3>
      <ul>
        {result.mitigation.playbook.map((step, i) => (
          <li key={i}>{step}</li>
        ))}
      </ul>
      <h4>Command Safety Validation</h4>
      <ul>
        {result.mitigation.commands.map((command, i) => (
          <li key={i}>
            <code>{command}</code>
            <span className={result.command_validation[i]?.allowed ? 'ok' : 'bad'}>
              {result.command_validation[i]?.allowed ? 'Allowed' : 'Blocked'}
            </span>
          </li>
        ))}
      </ul>
      <h4>SOAR Auto Playbook</h4>
      <ol>
        {(result.mitigation.soar_workflow || []).map((step, i) => (
          <li key={i}>{step}</li>
        ))}
      </ol>
    </section>
  )
}

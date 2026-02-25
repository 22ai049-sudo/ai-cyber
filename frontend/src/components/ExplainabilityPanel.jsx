export default function ExplainabilityPanel({ result }) {
  if (!result) return null

  return (
    <section className='card'>
      <h3>Explainability + Raw Output</h3>
      <p className='muted'>
        Threat analyzed by local Mistral 7B. Review this reasoning to learn why this incident was scored and mapped.
      </p>
      <h4>Model Correctness Validation</h4>
      <p className='muted'>
        Status: <strong>{result?.model_validation?.status || 'n/a'}</strong> | Score: {Math.round((result?.model_validation?.score || 0) * 100)}%
      </p>
      {result?.model_validation?.findings?.length > 0 && (
        <ul>
          {result.model_validation.findings.map((finding, idx) => (
            <li key={idx}>{finding}</li>
          ))}
        </ul>
      )}
      <h4>MITRE ATT&CK Mapping</h4>
      <ul>
        {(result?.mitre_attack || []).map((m, idx) => (
          <li key={idx}>{m.tactic} · {m.technique_id} · {m.technique_name}</li>
        ))}
        {!result?.mitre_attack?.length && <li>No direct ATT&CK mapping found from current telemetry.</li>}
      </ul>
      <pre>{result.reasoning}</pre>
    </section>
  )
}

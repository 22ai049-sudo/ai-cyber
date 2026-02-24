export default function ExplainabilityPanel({ result }) {
  if (!result) return null
  return <div className='card'><h3>LLM Explainability</h3><pre>{result.reasoning}</pre></div>
}

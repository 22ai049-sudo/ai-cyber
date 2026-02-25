export default function IncidentPanel({
  form,
  setForm,
  onSubmit,
  samples,
  onLoadSample,
  autoIndicators,
  onLoadAutomaticIndicator,
  busy,
  canSubmit,
  logSamples,
  onParseLog,
}) {
  return (
    <section className='card ingress-card'>
      <div className='card-title-row'>
        <h3>Threat Ingestion Control</h3>
        <span className='pill'>{form.ingestion_mode.toUpperCase()} MODE</span>
      </div>
      <p className='muted'>Choose manual analyst entry or automatic malicious-IP collection from global feeds.</p>
      <div className='row split'>
        <label>
          Source
          <input value={form.source} onChange={(e) => setForm({ ...form, source: e.target.value })} />
        </label>
        <label>
          Indicator
          <input value={form.indicator} onChange={(e) => setForm({ ...form, indicator: e.target.value })} />
        </label>
      </div>
      <label>
        Event Details
        <textarea rows={4} value={form.message} onChange={(e) => setForm({ ...form, message: e.target.value })} />
      </label>
      <div className='row split'>
        <label>
          Ingestion Mode
          <select
            value={form.ingestion_mode}
            onChange={(e) => setForm({ ...form, ingestion_mode: e.target.value, dataset_name: '' })}
          >
            <option value='manual'>Manual analyst input</option>
            <option value='automatic'>Automatic global malicious-IP feed</option>
          </select>
        </label>
        <label>
          Dataset trainer (optional)
          <select
            value={form.dataset_name}
            onChange={(e) => setForm({ ...form, dataset_name: e.target.value })}
            disabled={form.ingestion_mode !== 'manual'}
          >
            <option value=''>Select dataset sample</option>
            {samples.map((sample) => (
              <option key={sample.title} value={sample.dataset}>{sample.title}</option>
            ))}
          </select>
        </label>
      </div>

      <div className='actions'>
        <label className='check'>
          <input
            type='checkbox'
            checked={form.execute}
            onChange={(e) => setForm({ ...form, execute: e.target.checked })}
          />
          Enable safe auto-resolution in Docker sandbox
        </label>
        <button onClick={onSubmit} disabled={busy || !canSubmit}>
          {busy ? 'Analyzing...' : 'Analyze & Resolve Threat'}
        </button>
      </div>

      <div className='sample-strip'>
        {samples.map((sample) => (
          <button key={sample.title} className='ghost' onClick={() => onLoadSample(sample)}>{sample.title}</button>
        ))}
      </div>

      {form.ingestion_mode === 'automatic' && (
        <div className='sample-strip'>
          {autoIndicators.map((item) => (
            <button
              key={`${item.source}-${item.indicator}`}
              className='ghost'
              onClick={() => onLoadAutomaticIndicator(item)}
            >
              {item.indicator} · {item.source}
            </button>
          ))}
          {!autoIndicators.length && <span className='muted'>No automatic indicators loaded yet.</span>}
        </div>
      )}

      <div className='card log-card'>
        <h4>Real Log Ingestion (Sysmon / Suricata / Wazuh)</h4>
        <p className='muted'>Load a sample log and auto-parse indicator + context into manual analysis form.</p>
        <div className='sample-strip'>
          {Object.entries(logSamples || {}).map(([source, raw]) => (
            <button key={source} className='ghost' onClick={() => onParseLog(source, raw)}>
              Parse {source}
            </button>
          ))}
          {!Object.keys(logSamples || {}).length && <span className='muted'>No log samples available.</span>}
        </div>
      </div>
    </section>
  )
}

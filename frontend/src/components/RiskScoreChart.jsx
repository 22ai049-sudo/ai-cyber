import { Bar, BarChart, Cell, ResponsiveContainer, XAxis, YAxis } from 'recharts'

export default function RiskScoreChart({ result }) {
  if (!result) return null
  const data = [{ name: 'Confidence', score: Math.round(result.confidence * 100) }]
  const color = result.severity === 'critical' ? '#ff2b59' : result.severity === 'high' ? '#ff7a18' : '#4ecdc4'
  return <div className='card'><h3>Risk Severity: {result.severity.toUpperCase()}</h3><ResponsiveContainer width='100%' height={180}><BarChart data={data}><XAxis dataKey='name'/><YAxis domain={[0,100]}/><Bar dataKey='score'>{data.map((_,i)=><Cell key={i} fill={color}/>)}</Bar></BarChart></ResponsiveContainer></div>
}

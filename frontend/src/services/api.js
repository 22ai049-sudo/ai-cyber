import axios from 'axios'

const api = axios.create({ baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000' })

const authHeader = (token) => ({ headers: { Authorization: `Bearer ${token}` } })

export const login = async (username, password) => {
  const { data } = await api.post('/auth/login', { username, password })
  return data.access_token
}

export const processIncident = async (token, payload) => {
  const { data } = await api.post('/incidents/process', payload, authHeader(token))
  return data
}

export const getAudit = async (token, incidentId) => {
  const { data } = await api.get(`/incidents/${incidentId}/audit`, authHeader(token))
  return data
}

export const getIngestionSamples = async (token) => {
  const { data } = await api.get('/ingestion/samples', authHeader(token))
  return data.samples
}

export const getLiveIngestion = async (token) => {
  const { data } = await api.get('/ingestion/live', authHeader(token))
  return data
}

export const getAutomaticIngestion = async (token) => {
  const { data } = await api.get('/ingestion/automatic', authHeader(token))
  return data
}

export const getLogSamples = async (token) => {
  const { data } = await api.get('/ingestion/logs/samples', authHeader(token))
  return data.samples
}

export const parseSecurityLog = async (token, payload) => {
  const { data } = await api.post('/ingestion/logs/parse', payload, authHeader(token))
  return data
}

import axios from 'axios'

const api = axios.create({ baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000' })

export const login = async (username, password) => {
  const { data } = await api.post('/auth/login', { username, password })
  return data.access_token
}

export const processIncident = async (token, payload) => {
  const { data } = await api.post('/incidents/process', payload, {
    headers: { Authorization: `Bearer ${token}` },
  })
  return data
}

export const getAudit = async (token, incidentId) => {
  const { data } = await api.get(`/incidents/${incidentId}/audit`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  return data
}

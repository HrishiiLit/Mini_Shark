import { useState } from 'react'
import MiniShark from './components/MiniShark'
import Dashboard from './components/Dashboard'
import './index.css'

export default function App() {
  const [view, setView] = useState('analyzer')

  return view === 'analyzer' ? (
    <MiniShark onSwitchView={setView} />
  ) : (
    <div style={{ background: '#0d1117', minHeight: '100vh', color: '#e6edf3' }}>
      <Dashboard onSwitchView={setView} />
    </div>
  )
}

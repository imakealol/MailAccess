import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Home from './pages/Home'
import InvestigationView from './pages/InvestigationView'
import HistoryPage from './pages/HistoryPage'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/investigation/:id" element={<InvestigationView />} />
        <Route path="/history" element={<HistoryPage />} />
      </Routes>
    </BrowserRouter>
  )
}

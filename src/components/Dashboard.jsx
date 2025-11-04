import React, { useState } from 'react'

const TOKENS = {
  sameer: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q",
  ashley: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDE3MywiaWF0IjoxNzMwODMyMjMwLCJleHAiOjE3MzM0MjQyMzB9.u_xgNI_k9LZQZx8Ag9D0CsUVqrB5jLXX6lC6KpNOBhU"
}

const API_URL = "https://vauntapi.flyvaunt.com"

function Dashboard() {
  const [selectedAccount, setSelectedAccount] = useState('sameer')
  const [loading, setLoading] = useState(false)
  const [data, setData] = useState({
    user: null,
    flights: null,
    waitlist: null,
    upgrades: null,
    duffelOrders: null
  })
  const [error, setError] = useState(null)

  const fetchAPI = async (endpoint, token) => {
    const response = await fetch(`${API_URL}${endpoint}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    })
    if (!response.ok) {
      throw new Error(`API error: ${response.status}`)
    }
    return response.json()
  }

  const handleCheckAll = async () => {
    setLoading(true)
    setError(null)
    
    const token = TOKENS[selectedAccount]
    
    try {
      const [user, flights, waitlist, upgrades, duffelOrders] = await Promise.all([
        fetchAPI('/v1/user', token).catch(() => null),
        fetchAPI('/v1/flight', token).catch(() => null),
        fetchAPI('/v1/flight-waitlist', token).catch(() => null),
        fetchAPI('/v1/waitlist-upgrade', token).catch(() => null),
        fetchAPI('/v1/app/duffel/orders', token).catch(() => null)
      ])

      setData({
        user,
        flights,
        waitlist,
        upgrades,
        duffelOrders
      })
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const formatDate = (timestamp) => {
    if (!timestamp) return 'N/A'
    const date = new Date(timestamp * 1000)
    return date.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  const formatPriorityScore = (score) => {
    if (!score) return 'N/A'
    const date = new Date(score * 1000)
    const now = new Date()
    const years = ((score * 1000 - now.getTime()) / (1000 * 60 * 60 * 24 * 365)).toFixed(1)
    return `${score.toLocaleString()} (${date.toLocaleDateString()}) [+${years} years]`
  }

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-xl shadow-lg p-6">
        <h2 className="text-2xl font-bold text-gray-900 mb-4">API Testing Controls</h2>
        
        <div className="flex items-center gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Select Account</label>
            <select
              value={selectedAccount}
              onChange={(e) => setSelectedAccount(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="sameer">Sameer Chopra (Cabin+)</option>
              <option value="ashley">Ashley Rager (Free)</option>
            </select>
          </div>

          <div className="pt-6">
            <button
              onClick={handleCheckAll}
              disabled={loading}
              className="px-8 py-3 bg-gradient-to-r from-blue-600 to-indigo-600 text-white font-semibold rounded-lg shadow-md hover:from-blue-700 hover:to-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all transform hover:scale-105"
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                  Checking...
                </span>
              ) : (
                <span className="flex items-center gap-2">
                  🔍 Check All APIs
                </span>
              )}
            </button>
          </div>
        </div>

        {error && (
          <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg">
            <p className="text-red-800 font-medium">❌ Error: {error}</p>
          </div>
        )}
      </div>

      {data.user && (
        <>
          <div className="bg-white rounded-xl shadow-lg p-6">
            <h3 className="text-xl font-bold text-gray-900 mb-4 flex items-center gap-2">
              👤 User Information
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              <div className="p-4 bg-blue-50 rounded-lg">
                <p className="text-sm text-gray-600 font-medium">Name</p>
                <p className="text-lg font-bold text-gray-900">{data.user.firstName} {data.user.lastName}</p>
              </div>
              <div className="p-4 bg-green-50 rounded-lg">
                <p className="text-sm text-gray-600 font-medium">Email</p>
                <p className="text-lg font-bold text-gray-900">{data.user.email}</p>
              </div>
              <div className="p-4 bg-purple-50 rounded-lg">
                <p className="text-sm text-gray-600 font-medium">Phone</p>
                <p className="text-lg font-bold text-gray-900">{data.user.phoneNumber || 'N/A'}</p>
              </div>
              <div className="p-4 bg-yellow-50 rounded-lg">
                <p className="text-sm text-gray-600 font-medium">Priority Score</p>
                <p className="text-sm font-mono text-gray-900">{formatPriorityScore(data.user.priorityScore)}</p>
              </div>
              <div className="p-4 bg-pink-50 rounded-lg">
                <p className="text-sm text-gray-600 font-medium">Membership</p>
                <p className="text-lg font-bold text-gray-900">
                  {data.user.license?.membershipTier?.name || 'Free Account'}
                </p>
              </div>
              <div className="p-4 bg-indigo-50 rounded-lg">
                <p className="text-sm text-gray-600 font-medium">Subscription Status</p>
                <p className="text-lg font-bold text-gray-900">
                  {data.user.subscriptionStatus === 3 ? '✅ Active' : '❌ Inactive'}
                </p>
              </div>
            </div>
          </div>

          {data.flights && data.flights.length > 0 && (
            <div className="bg-white rounded-xl shadow-lg p-6">
              <h3 className="text-xl font-bold text-gray-900 mb-4 flex items-center gap-2">
                ✈️ Available Flights ({data.flights.length})
              </h3>
              <div className="space-y-4 max-h-96 overflow-y-auto">
                {data.flights.map((flight) => (
                  <div key={flight.id} className="p-4 border border-gray-200 rounded-lg hover:border-blue-300 hover:shadow-md transition-all">
                    <div className="flex items-center justify-between mb-2">
                      <div>
                        <p className="text-lg font-bold text-gray-900">
                          {flight.departure?.icao} → {flight.arrival?.icao}
                        </p>
                        <p className="text-sm text-gray-600">
                          {flight.departure?.name} to {flight.arrival?.name}
                        </p>
                      </div>
                      <div className="text-right">
                        <p className="text-sm font-medium text-gray-700">
                          {formatDate(flight.scheduledDeparture)}
                        </p>
                        <span className={`inline-block px-3 py-1 rounded-full text-xs font-semibold ${
                          flight.status === 'OPEN' ? 'bg-green-100 text-green-800' :
                          flight.status === 'CLOSED' ? 'bg-red-100 text-red-800' :
                          'bg-gray-100 text-gray-800'
                        }`}>
                          {flight.status}
                        </span>
                      </div>
                    </div>
                    <div className="grid grid-cols-3 gap-4 mt-3 text-sm">
                      <div>
                        <p className="text-gray-600">Aircraft</p>
                        <p className="font-medium">{flight.aircraft?.name || 'N/A'}</p>
                      </div>
                      <div>
                        <p className="text-gray-600">Available Seats</p>
                        <p className="font-medium">{flight.seatsAvailable || 0}</p>
                      </div>
                      <div>
                        <p className="text-gray-600">Flight ID</p>
                        <p className="font-mono font-medium">#{flight.id}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {data.waitlist && data.waitlist.length > 0 && (
            <div className="bg-white rounded-xl shadow-lg p-6">
              <h3 className="text-xl font-bold text-gray-900 mb-4 flex items-center gap-2">
                📋 Your Waitlist ({data.waitlist.length})
              </h3>
              <div className="space-y-4">
                {data.waitlist.map((entry) => (
                  <div key={entry.id} className="p-4 border-l-4 border-blue-500 bg-blue-50 rounded-lg">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-lg font-bold text-gray-900">
                          Flight #{entry.flight?.id}
                        </p>
                        <p className="text-sm text-gray-600">
                          {entry.flight?.departure?.icao} → {entry.flight?.arrival?.icao}
                        </p>
                      </div>
                      <div className="text-right">
                        <p className="text-3xl font-bold text-blue-600">#{entry.position}</p>
                        <p className="text-sm text-gray-600">Position</p>
                      </div>
                    </div>
                    <div className="mt-3 text-sm text-gray-700">
                      <p>Scheduled: {formatDate(entry.flight?.scheduledDeparture)}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {data.upgrades && data.upgrades.length > 0 && (
            <div className="bg-white rounded-xl shadow-lg p-6">
              <h3 className="text-xl font-bold text-gray-900 mb-4 flex items-center gap-2">
                🎁 Priority Upgrades ({data.upgrades.length})
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {data.upgrades.map((upgrade) => (
                  <div key={upgrade.id} className="p-4 border border-gray-200 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <p className="text-lg font-bold text-gray-900">Upgrade #{upgrade.id}</p>
                      <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                        upgrade.used ? 'bg-gray-100 text-gray-800' : 'bg-green-100 text-green-800'
                      }`}>
                        {upgrade.used ? 'Used' : 'Available'}
                      </span>
                    </div>
                    <div className="space-y-1 text-sm">
                      <p className="text-gray-600">
                        Type: <span className="font-medium">{upgrade.type}</span>
                      </p>
                      <p className="text-gray-600">
                        Cost: <span className="font-medium">
                          {upgrade.type === 'base_free' ? '🆓 FREE' : `$${(upgrade.costInCents / 100).toFixed(2)}`}
                        </span>
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {data.duffelOrders && (
            <div className="bg-white rounded-xl shadow-lg p-6">
              <h3 className="text-xl font-bold text-gray-900 mb-4 flex items-center gap-2">
                🌐 Duffel Bookings (Commercial Flights/Hotels)
              </h3>
              {data.duffelOrders.orders && data.duffelOrders.orders.length > 0 ? (
                <div className="space-y-4">
                  {data.duffelOrders.orders.map((order, idx) => (
                    <div key={idx} className="p-4 border border-gray-200 rounded-lg">
                      <pre className="text-sm">{JSON.stringify(order, null, 2)}</pre>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-8 text-center bg-gray-50 rounded-lg">
                  <p className="text-gray-600">No commercial flight or hotel bookings found</p>
                  <p className="text-sm text-gray-500 mt-2">
                    Book through the Vaunt mobile app to see bookings here
                  </p>
                </div>
              )}
            </div>
          )}
        </>
      )}

      {!data.user && !loading && (
        <div className="bg-white rounded-xl shadow-lg p-12 text-center">
          <div className="text-6xl mb-4">📊</div>
          <h3 className="text-2xl font-bold text-gray-900 mb-2">Welcome to Vaunt API Dashboard</h3>
          <p className="text-gray-600 mb-6">
            Select an account and click "Check All APIs" to view comprehensive flight data, waitlist status, and priority scores.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-left mt-8">
            <div className="p-4 bg-blue-50 rounded-lg">
              <p className="text-lg font-bold mb-2">✈️ Flights</p>
              <p className="text-sm text-gray-600">View all available flights with schedules and status</p>
            </div>
            <div className="p-4 bg-green-50 rounded-lg">
              <p className="text-lg font-bold mb-2">📋 Waitlist</p>
              <p className="text-sm text-gray-600">Check your waitlist positions and priority</p>
            </div>
            <div className="p-4 bg-purple-50 rounded-lg">
              <p className="text-lg font-bold mb-2">🎁 Upgrades</p>
              <p className="text-sm text-gray-600">See available priority upgrades</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default Dashboard

import React, { useCallback, useMemo, useState } from 'react'

const API_URL = 'https://vauntapi.flyvaunt.com'

const ACCOUNTS = {
  sameer: {
    key: 'sameer',
    label: 'Sameer Chopra (Cabin+)',
    token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q',
    phone: '+13035234453',
    email: 'sameer.s.chopra@gmail.com',
    userId: 20254
  },
  ashley: {
    key: 'ashley',
    label: 'Ashley Rager (Free)',
    token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoxNzEyMDgsImlhdCI6MTc2MjIyNTUwMSwiZXhwIjoxNzY0ODE3NTAxfQ.TtZeO8zr_3aoLe21AmLGMsLj-ACxXqBh6cKNph_9dYg',
    phone: '+17203521547',
    email: 'ashleyrager15@yahoo.com',
    userId: 171208
  }
}

const AIRPORT_LOOKUP = {
  denver: ['DEN', 'APA', 'BJC', 'FTG', 'COS'],
  tampa: ['TPA', 'PIE', 'TPF', 'SRQ', 'MCO', 'ORL', 'ISM', 'SFB'],
  orlando: ['MCO', 'ORL', 'ISM', 'SFB', 'TPA'],
  phoenix: ['PHX', 'SCF', 'DVT'],
  atlanta: ['PDK', 'FTY', 'ATL', 'LZU'],
  dallas: ['DAL', 'DFW', 'ADS'],
  miami: ['MIA', 'OPF', 'TMB', 'FLL']
}

const accountOptions = Object.values(ACCOUNTS)

const randomId = () => {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) return crypto.randomUUID()
  return `${Date.now()}-${Math.random().toString(36).slice(2)}`
}

const classNames = (...values) => values.filter(Boolean).join(' ')

const formatIsoDate = (iso) => {
  if (!iso) return 'Unknown'
  try {
    const date = new Date(iso)
    return new Intl.DateTimeFormat('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      timeZoneName: 'short'
    }).format(date)
  } catch {
    return iso
  }
}

const formatPriorityScore = (score) => {
  if (!score) return 'N/A'
  const date = new Date(score * 1000)
  const deltaYears = ((date.getTime() - Date.now()) / (1000 * 60 * 60 * 24 * 365)).toFixed(1)
  return `${score.toLocaleString()} (${date.toLocaleDateString()} | +${deltaYears} yrs)`
}

const deriveAirportsForCity = (city, flights) => {
  const set = new Set()
  const lower = city.toLowerCase()
  const predefined = AIRPORT_LOOKUP[lower]
  if (predefined) predefined.forEach((code) => set.add(code.toUpperCase()))

  flights.forEach((flight) => {
    const dep = flight?.departAirport
    if (!dep) return
    const candidates = [
      dep.city,
      dep.name,
      dep.code,
      dep.codeIata,
      dep.codeFaa
    ]
    if (candidates.some((value) => (value || '').toLowerCase().includes(lower))) {
      const code = (dep.codeIata || dep.code || dep.codeFaa || '').toUpperCase()
      if (code) set.add(code)
    }
  })

  return Array.from(set)
}

const computeMatches = (flights, watchList) =>
  watchList
    .map((watch) => {
      const matches = flights.filter((flight) => {
        const dep = flight?.departAirport
        if (!dep) return false
        const code = (dep.codeIata || dep.code || dep.codeFaa || '').toUpperCase()
        return watch.airports.includes(code)
      })
      return matches.length
        ? { watch, flights: matches }
        : null
    })
    .filter(Boolean)

function Dashboard() {
  const [selectedAccountKey, setSelectedAccountKey] = useState('sameer')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [logs, setLogs] = useState([])
  const [data, setData] = useState({
    user: null,
    flights: [],
    duffelOrders: null
  })
  const [actionBusy, setActionBusy] = useState(null)
  const [watchCity, setWatchCity] = useState('')
  const [watchList, setWatchList] = useState([])
  const [matches, setMatches] = useState([])

  const account = useMemo(() => ACCOUNTS[selectedAccountKey], [selectedAccountKey])

  const appendLog = useCallback((message, level = 'info') => {
    setLogs((prev) => [
      {
        id: randomId(),
        timestamp: new Date().toLocaleTimeString(),
        level,
        message
      },
      ...prev
    ])
  }, [])

  const rawRequest = useCallback(
    async (accountKey, endpoint, { method = 'GET', body, headers = {}, mute401 = false } = {}) => {
      const acct = ACCOUNTS[accountKey]
      const response = await fetch(`${API_URL}${endpoint}`, {
        method,
        headers: {
          Authorization: `Bearer ${acct.token}`,
          'Content-Type': 'application/json',
          ...headers
        },
        body: body ? JSON.stringify(body) : undefined
      })

      if (response.status === 401 && !mute401) {
        appendLog(`🔄 JWT expired for ${acct.label}. Re-triggering SMS → ${acct.phone}`, 'warn')
        await fetch(`${API_URL}/v1/auth/initiateSignIn`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ phoneNumber: acct.phone })
        }).catch(() => null)
        throw new Error('401 Unauthorized – SMS re-sent')
      }

      const text = await response.text()
      let json = null
      if (text) {
        try {
          json = JSON.parse(text)
        } catch {
          /* plaintext */
        }
      }

      return {
        status: response.status,
        ok: response.ok,
        text,
        json
      }
    },
    [appendLog]
  )

  const fetchAPI = useCallback(
    async (accountKey, endpoint) => {
      const result = await rawRequest(accountKey, endpoint)
      if (!result.ok) {
        throw new Error(`${endpoint} → ${result.status}`)
      }
      return result.json
    },
    [rawRequest]
  )

  const handleCheckAll = useCallback(async () => {
    setLoading(true)
    setError(null)

    try {
      const [user, flights, duffelOrders] = await Promise.all([
        fetchAPI(selectedAccountKey, '/v1/user'),
        fetchAPI(selectedAccountKey, '/v1/flight').catch(() => []),
        fetchAPI(selectedAccountKey, '/v1/app/duffel/orders').catch(() => null)
      ])

      setData({
        user: user || null,
        flights: Array.isArray(flights) ? flights : [],
        duffelOrders
      })

      const upcoming = computeMatches(Array.isArray(flights) ? flights : [], watchList)
      setMatches(upcoming)
      upcoming.forEach((match) => {
        appendLog(
          `🚨 ${match.watch.city.toUpperCase()} → flights ${match.flights
            .map((f) => `#${f.id} (${(f.departAirport?.codeIata || f.departAirport?.code || '').toUpperCase()})`)
            .join(', ')}`,
          'warn'
        )
      })

      appendLog(`✅ Refreshed data for ${ACCOUNTS[selectedAccountKey].label}`, 'info')
    } catch (err) {
      setError(err.message)
      appendLog(`❌ ${err.message}`, 'error')
    } finally {
      setLoading(false)
    }
  }, [appendLog, fetchAPI, selectedAccountKey, watchList])

  const triggerSms = useCallback(async () => {
    setActionBusy('sms')
    try {
      const res = await rawRequest(account.key, '/v1/auth/initiateSignIn', {
        method: 'POST',
        body: { phoneNumber: account.phone },
        mute401: true
      })
      appendLog(`📲 SMS queued for ${account.phone} → ${res.status}`, res.ok ? 'info' : 'warn')
    } catch (err) {
      appendLog(`❌ Failed to trigger SMS: ${err.message}`, 'error')
    } finally {
      setActionBusy(null)
    }
  }, [account.key, account.phone, appendLog, rawRequest])

  const attemptTrial = useCallback(async () => {
    setActionBusy('trial')
    const endpoints = [
      { method: 'POST', endpoint: '/v1/subscription/trial' },
      { method: 'POST', endpoint: '/v1/subscription/trial/start' },
      { method: 'POST', endpoint: '/v1/subscription/trial/claim' },
      { method: 'POST', endpoint: '/v1/trial/start' },
      { method: 'GET', endpoint: '/v1/trial/status' }
    ]

    try {
      for (const attempt of endpoints) {
        const res = await rawRequest(account.key, attempt.endpoint, {
          method: attempt.method
        })
        appendLog(
          `${attempt.method} ${attempt.endpoint} → ${res.status}${
            res.json ? ` :: ${JSON.stringify(res.json)}` : res.text ? ` :: ${res.text}` : ''
          }`,
          res.ok ? 'info' : 'error'
        )
        if (res.ok) break
      }
    } catch (err) {
      appendLog(`❌ Trial probe failed: ${err.message}`, 'error')
    } finally {
      setActionBusy(null)
    }
  }, [account.key, appendLog, rawRequest])

  const addWatchCity = useCallback(() => {
    const trimmed = watchCity.trim()
    if (!trimmed) return
    const normalized = trimmed.toLowerCase()
    if (watchList.some((watch) => watch.city === normalized)) {
      appendLog(`ℹ️ Already watching ${trimmed}`, 'info')
      setWatchCity('')
      return
    }

    const airports = deriveAirportsForCity(normalized, data.flights)
    if (airports.length === 0) {
      appendLog(`⚠️ No matching airports found for "${trimmed}". Added anyway.`, 'warn')
    } else {
      appendLog(`🎯 Watching ${trimmed} airports → ${airports.join(', ')}`, 'info')
    }

    const watch = { id: randomId(), city: normalized, airports }
    setWatchList((prev) => [...prev, watch])

    if (data.flights.length > 0) {
      const hits = computeMatches(data.flights, [...watchList, watch])
      setMatches(hits)
    }
    setWatchCity('')
  }, [appendLog, data.flights, watchCity, watchList])

  const removeWatchCity = useCallback(
    (id) => {
      setWatchList((prev) => prev.filter((watch) => watch.id !== id))
      const updated = watchList.filter((watch) => watch.id !== id)
      setMatches(computeMatches(data.flights, updated))
    },
    [data.flights, watchList]
  )

  const attemptWaitlistRemoval = useCallback(
    async (flight, entrant) => {
      setActionBusy(`remove-${flight.id}-${entrant.id}`)
      appendLog(
        `⚔️ Attempting removal of user ${entrant.id} (${entrant.firstName} ${entrant.lastName}) from flight ${flight.id}`,
        'warn'
      )

      const attempts = [
        { method: 'DELETE', endpoint: `/v1/waitlist/${flight.id}` },
        { method: 'POST', endpoint: `/v1/waitlist/${flight.id}/leave` },
        { method: 'DELETE', endpoint: `/v1/flight/${flight.id}/entrants/${entrant.id}` },
        { method: 'DELETE', endpoint: `/v1/flight-waitlist/${entrant.entrantId}` },
        { method: 'POST', endpoint: `/v1/flight/${flight.id}/leave`, body: { userId: account.userId } }
      ]

      try {
        for (const attempt of attempts) {
          const res = await rawRequest(account.key, attempt.endpoint, {
            method: attempt.method,
            body: attempt.body
          })
          appendLog(
            `${attempt.method} ${attempt.endpoint} → ${res.status}${
              res.json ? ` :: ${JSON.stringify(res.json)}` : res.text ? ` :: ${res.text}` : ''
            }`,
            res.ok ? 'info' : 'error'
          )
          if (res.ok) break
        }
      } catch (err) {
        appendLog(`❌ Removal attempt failed: ${err.message}`, 'error')
      } finally {
        setActionBusy(null)
      }
    },
    [account.key, account.userId, appendLog, rawRequest]
  )

  const attemptAutoBook = useCallback(
    async (flightId) => {
      setActionBusy(`autobook-${flightId}`)
      appendLog(`🤖 Attempting auto-book flow for flight ${flightId}`, 'warn')

      const attempts = [
        { method: 'POST', endpoint: `/v1/flight/${flightId}/book` },
        { method: 'POST', endpoint: `/v1/flight/${flightId}/claim` },
        { method: 'POST', endpoint: `/v1/flight/${flightId}/confirm` },
        { method: 'POST', endpoint: `/v1/flight/${flightId}/accept` },
        { method: 'POST', endpoint: `/v1/flight/${flightId}/select-winner`, body: { userId: account.userId } }
      ]

      try {
        for (const attempt of attempts) {
          const res = await rawRequest(account.key, attempt.endpoint, {
            method: attempt.method,
            body: attempt.body
          })
          appendLog(
            `${attempt.method} ${attempt.endpoint} → ${res.status}${
              res.json ? ` :: ${JSON.stringify(res.json)}` : res.text ? ` :: ${res.text}` : ''
            }`,
            res.ok ? 'info' : 'error'
          )
          if (res.ok) break
        }
      } catch (err) {
        appendLog(`❌ Auto-book failed: ${err.message}`, 'error')
      } finally {
        setActionBusy(null)
      }
    },
    [account.key, account.userId, appendLog, rawRequest]
  )

  const hasLegacyFlights = useMemo(() => {
    if (data.flights.length === 0) return false
    return data.flights.every((flight) => {
      const depart = flight.departDateTime ? new Date(flight.departDateTime) : null
      return depart && depart.getFullYear() <= 2024
    })
  }, [data.flights])

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-xl shadow-lg p-6">
        <h2 className="text-2xl font-bold text-gray-900 mb-4">Vaunt API Playground</h2>
        <div className="grid gap-6 md:grid-cols-[260px_auto]">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Account</label>
            <select
              value={selectedAccountKey}
              onChange={(event) => setSelectedAccountKey(event.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            >
              {accountOptions.map((option) => (
                <option key={option.key} value={option.key}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
          <div className="flex flex-wrap items-end gap-3">
            <button
              onClick={handleCheckAll}
              disabled={loading}
              className={classNames(
                'px-6 py-3 rounded-lg font-semibold text-white bg-gradient-to-br from-blue-600 to-indigo-600 shadow-md transition-transform hover:scale-[1.02]',
                loading && 'opacity-50 cursor-not-allowed hover:scale-100'
              )}
            >
              {loading ? 'Refreshing…' : '🔍 Pull Live Data'}
            </button>
            <button
              onClick={triggerSms}
              disabled={actionBusy !== null}
              className={classNames(
                'px-4 py-2 rounded-lg border border-red-400 text-red-600 bg-red-50 hover:bg-red-100 transition-all',
                actionBusy && 'opacity-50 cursor-not-allowed'
              )}
            >
              📲 Trigger Login SMS
            </button>
            <button
              onClick={attemptTrial}
              disabled={actionBusy !== null}
              className={classNames(
                'px-4 py-2 rounded-lg border border-amber-400 text-amber-600 bg-amber-50 hover:bg-amber-100 transition-all',
                actionBusy && 'opacity-50 cursor-not-allowed'
              )}
            >
              🧪 Probe Trial Endpoints
            </button>
          </div>
        </div>
        {error && (
          <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg text-red-800">
            ❌ {error}
          </div>
        )}
        {hasLegacyFlights && (
          <div className="mt-4 p-4 bg-amber-50 border border-amber-200 rounded-lg text-amber-800 text-sm">
            ⚠️ The API is still serving 2024 flight data. Features work, but results won’t reflect current schedules.
          </div>
        )}
      </div>

      <div className="bg-white rounded-xl shadow-lg p-6">
        <h3 className="text-xl font-bold text-gray-900 mb-4 flex items-center gap-2">🎯 City Watchlist</h3>
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex-1 min-w-[220px]">
            <label className="block text-sm text-gray-600 mb-1">City or Airport</label>
            <input
              value={watchCity}
              onChange={(event) => setWatchCity(event.target.value)}
              placeholder="e.g. Denver, Tampa, Dallas"
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
          <button
            onClick={addWatchCity}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg shadow hover:bg-blue-700 transition-all"
          >
            Add Watch
          </button>
        </div>
        {watchList.length === 0 ? (
          <p className="text-sm text-gray-500 mt-4">No cities watched yet. Add one to start highlighting flights.</p>
        ) : (
          <div className="mt-4 space-y-3">
            {watchList.map((watch) => (
              <div key={watch.id} className="flex items-center justify-between border border-gray-200 rounded-lg px-4 py-2">
                <div>
                  <p className="font-semibold text-gray-800 capitalize">{watch.city}</p>
                  <p className="text-xs text-gray-500">
                    Airports: {watch.airports.length > 0 ? watch.airports.join(', ') : 'None detected yet'}
                  </p>
                </div>
                <button
                  onClick={() => removeWatchCity(watch.id)}
                  className="text-sm text-red-600 hover:text-red-800"
                >
                  Remove
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {data.user && (
        <div className="bg-white rounded-xl shadow-lg p-6">
          <h3 className="text-xl font-bold text-gray-900 mb-4 flex items-center gap-2">👤 Account Snapshot</h3>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            <div className="p-4 rounded-lg bg-blue-50">
              <p className="text-sm text-gray-600">Name</p>
              <p className="text-lg font-semibold text-gray-900">
                {data.user.firstName} {data.user.lastName}
              </p>
            </div>
            <div className="p-4 rounded-lg bg-green-50">
              <p className="text-sm text-gray-600">Email</p>
              <p className="text-lg font-semibold text-gray-900">{data.user.email}</p>
            </div>
            <div className="p-4 rounded-lg bg-purple-50">
              <p className="text-sm text-gray-600">Phone</p>
              <p className="text-lg font-semibold text-gray-900">{data.user.phoneNumber}</p>
            </div>
            <div className="p-4 rounded-lg bg-amber-50">
              <p className="text-sm text-gray-600">Priority Score</p>
              <p className="text-sm font-mono text-gray-900">{formatPriorityScore(data.user.priorityScore)}</p>
            </div>
            <div className="p-4 rounded-lg bg-pink-50">
              <p className="text-sm text-gray-600">Membership Tier</p>
              <p className="text-lg font-semibold text-gray-900">
                {data.user.license?.membershipTier?.name || 'Free / base'}
              </p>
            </div>
            <div className="p-4 rounded-lg bg-indigo-50">
              <p className="text-sm text-gray-600">Subscription Status</p>
              <p className="text-lg font-semibold text-gray-900">
                {data.user.subscriptionStatus === 3 ? '✅ Active' : '❌ Inactive'}
              </p>
            </div>
          </div>
        </div>
      )}

      {matches.length > 0 && (
        <div className="bg-white rounded-xl shadow-lg p-6 border border-blue-200">
          <h3 className="text-xl font-bold text-blue-900 mb-4 flex items-center gap-2">🚨 Matches for Watchlist</h3>
          <div className="space-y-4">
            {matches.map((match) => (
              <div key={match.watch.id} className="border border-blue-200 rounded-lg p-4 bg-blue-50">
                <div className="flex items-center justify-between">
                  <p className="text-lg font-semibold capitalize text-blue-900">{match.watch.city}</p>
                  <p className="text-sm text-blue-700">
                    Airports: {match.watch.airports.length > 0 ? match.watch.airports.join(', ') : 'N/A'}
                  </p>
                </div>
                <div className="mt-3 space-y-3">
                  {match.flights.map((flight) => (
                    <div key={`${match.watch.id}-${flight.id}`} className="p-3 bg-white rounded border border-blue-200">
                      <div className="flex flex-wrap justify-between items-center gap-3">
                        <div>
                          <p className="font-semibold text-gray-900">
                            Flight #{flight.id} ·{' '}
                            {(flight.departAirport?.codeIata || flight.departAirport?.code || '').toUpperCase()} →{' '}
                            {(flight.arriveAirport?.codeIata || flight.arriveAirport?.code || '').toUpperCase()}
                          </p>
                          <p className="text-xs text-gray-500">
                            Departs {formatIsoDate(flight.departDateTime)} · Closeout {formatIsoDate(flight.closeoutDateTime)}
                          </p>
                        </div>
                        <button
                          onClick={() => attemptAutoBook(flight.id)}
                          disabled={actionBusy !== null}
                          className={classNames(
                            'px-3 py-1 text-xs rounded bg-blue-600 text-white shadow hover:bg-blue-700 transition-all',
                            actionBusy && 'opacity-50 cursor-not-allowed'
                          )}
                        >
                          🤖 Attempt Auto-Book
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {data.flights.length > 0 && (
        <div className="bg-white rounded-xl shadow-lg p-6">
          <h3 className="text-xl font-bold text-gray-900 mb-4 flex items-center gap-2">
            ✈️ Flight Explorer (first {Math.min(data.flights.length, 12)} of {data.flights.length})
          </h3>
          <p className="text-sm text-gray-600 mb-4">
            Every card is rendered directly from the API payload, including Azure blob banner images and the full entrant list.
          </p>
          <div className="space-y-6">
            {data.flights.slice(0, 12).map((flight) => {
              const entrants = Array.isArray(flight.entrants) ? flight.entrants : []
              return (
                <div key={flight.id} className="border border-gray-200 rounded-lg overflow-hidden shadow-sm">
                  {flight.bannerUrl && (
                    <div className="h-40 bg-gray-100">
                      <img src={flight.bannerUrl} alt={`Flight ${flight.id}`} className="w-full h-full object-cover" />
                    </div>
                  )}
                  <div className="p-5 space-y-4">
                    <div className="flex flex-wrap justify-between items-start gap-3">
                      <div>
                        <p className="text-lg font-semibold text-gray-900">
                          {(flight.departAirport?.codeIata || flight.departAirport?.code || '???').toUpperCase()} →{' '}
                          {(flight.arriveAirport?.codeIata || flight.arriveAirport?.code || '???').toUpperCase()}
                        </p>
                        <p className="text-sm text-gray-600">
                          {flight.departAirport?.name || 'Unknown departure'} →{' '}
                          {flight.arriveAirport?.name || 'Unknown arrival'}
                        </p>
                        <p className="text-xs text-gray-500 mt-1">
                          Departs {formatIsoDate(flight.departDateTime)} · Closeout {formatIsoDate(flight.closeoutDateTime)}
                        </p>
                      </div>
                      <div className="text-right">
                        <p className="text-sm text-gray-500">Flight #{flight.id}</p>
                        <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold bg-slate-100 text-slate-700">
                          Queue size: {entrants.length}
                        </span>
                      </div>
                    </div>

                    {entrants.length > 0 && (
                      <div className="bg-slate-50 border border-slate-200 rounded-md p-4">
                        <p className="text-sm font-semibold text-slate-700 mb-3">
                          Waitlist Entrants (any authenticated user can retrieve this!)
                        </p>
                        <div className="overflow-x-auto">
                          <table className="min-w-full text-sm text-left">
                            <thead>
                              <tr className="text-xs uppercase text-slate-500">
                                <th className="px-3 py-2">User ID</th>
                                <th className="px-3 py-2">Name</th>
                                <th className="px-3 py-2">Queue Position</th>
                                <th className="px-3 py-2">Carbon Offset</th>
                                <th className="px-3 py-2">Actions</th>
                              </tr>
                            </thead>
                            <tbody>
                              {entrants.slice(0, 10).map((entrant) => (
                                <tr key={`${flight.id}-${entrant.id}`} className="border-t border-slate-200">
                                  <td className="px-3 py-2 font-mono text-xs text-slate-600">{entrant.id}</td>
                                  <td className="px-3 py-2 text-slate-800">
                                    {entrant.firstName} {entrant.lastName}
                                  </td>
                                  <td className="px-3 py-2 text-slate-600">
                                    #{entrant.queuePosition ?? '—'}
                                  </td>
                                  <td className="px-3 py-2 text-slate-600">
                                    {entrant.isCarbonOffsetEnrolled ? '✅' : '❌'}
                                  </td>
                                  <td className="px-3 py-2">
                                    <button
                                      onClick={() => attemptWaitlistRemoval(flight, entrant)}
                                      disabled={actionBusy !== null}
                                      className={classNames(
                                        'px-3 py-1 text-xs rounded border border-red-400 text-red-600 bg-red-50 hover:bg-red-100 transition',
                                        actionBusy && 'opacity-50 cursor-not-allowed'
                                      )}
                                    >
                                      Remove (multi-endpoint attack)
                                    </button>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                        {entrants.length > 10 && (
                          <p className="text-xs text-slate-500 mt-2">{entrants.length - 10} additional entrants not shown.</p>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      <div className="bg-white rounded-xl shadow-lg p-6">
        <h3 className="text-xl font-bold text-gray-900 mb-4 flex items-center gap-2">🪤 Action Log</h3>
        {logs.length === 0 ? (
          <p className="text-sm text-slate-500">No activity yet. Run some actions above to populate the log.</p>
        ) : (
          <ul className="max-h-64 overflow-y-auto space-y-2 text-sm">
            {logs.map((entry) => (
              <li
                key={entry.id}
                className={classNames(
                  'p-3 rounded border',
                  entry.level === 'error'
                    ? 'bg-red-50 border-red-200 text-red-700'
                    : entry.level === 'warn'
                    ? 'bg-amber-50 border-amber-200 text-amber-700'
                    : 'bg-slate-50 border-slate-200 text-slate-700'
                )}
              >
                <span className="font-mono text-xs mr-2 text-slate-500">{entry.timestamp}</span>
                {entry.message}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}

export default Dashboard

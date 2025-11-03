import React, { useState } from 'react'
import { useDropzone } from 'react-dropzone'

function FileTree({ items, extractId }) {
  const [expanded, setExpanded] = useState({})

  const toggleExpand = (path) => {
    setExpanded(prev => ({ ...prev, [path]: !prev[path] }))
  }

  const handleDownload = (filepath) => {
    const url = `/api/download/${extractId}/${filepath}`
    window.open(url, '_blank')
  }

  const renderTree = (items, level = 0) => {
    return items.map((item, idx) => (
      <div key={idx} style={{ marginLeft: `${level * 20}px` }} className="py-1">
        {item.type === 'directory' ? (
          <div>
            <div 
              className="flex items-center gap-2 cursor-pointer hover:bg-gray-100 p-1 rounded"
              onClick={() => toggleExpand(item.path)}
            >
              <span>{expanded[item.path] ? '📂' : '📁'}</span>
              <span className="font-medium">{item.name}</span>
            </div>
            {expanded[item.path] && item.children && (
              <div>{renderTree(item.children, level + 1)}</div>
            )}
          </div>
        ) : (
          <div className="flex items-center gap-2 hover:bg-gray-100 p-1 rounded group">
            <span>📄</span>
            <span className="flex-1">{item.name}</span>
            <span className="text-xs text-gray-500">
              {(item.size / 1024).toFixed(2)} KB
            </span>
            <button
              onClick={() => handleDownload(item.path)}
              className="ml-2 px-2 py-1 text-xs bg-blue-500 text-white rounded opacity-0 group-hover:opacity-100 transition-opacity"
            >
              Download
            </button>
          </div>
        )}
      </div>
    ))
  }

  return <div className="text-sm">{renderTree(items)}</div>
}

function App() {
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  const onDrop = async (acceptedFiles) => {
    const file = acceptedFiles[0]
    if (!file) return

    if (!file.name.endsWith('.apk')) {
      setError('Please upload a valid APK file')
      return
    }

    setLoading(true)
    setError(null)
    setResult(null)

    const formData = new FormData()
    formData.append('file', file)

    try {
      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData
      })

      const data = await response.json()
      
      if (data.success) {
        setResult(data)
      } else {
        setError(data.error || 'Failed to process APK')
      }
    } catch (err) {
      setError('Error uploading file: ' + err.message)
    } finally {
      setLoading(false)
    }
  }

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/vnd.android.package-archive': ['.apk']
    },
    multiple: false
  })

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-2">APK Decompiler</h1>
          <p className="text-gray-600">Upload an APK file to extract and analyze its contents</p>
        </div>

        <div
          {...getRootProps()}
          className={`border-2 border-dashed rounded-lg p-12 text-center cursor-pointer transition-colors ${
            isDragActive ? 'border-blue-500 bg-blue-50' : 'border-gray-300 hover:border-gray-400'
          }`}
        >
          <input {...getInputProps()} />
          <div className="text-6xl mb-4">📦</div>
          {isDragActive ? (
            <p className="text-lg text-blue-600">Drop the APK file here</p>
          ) : (
            <div>
              <p className="text-lg text-gray-700 mb-2">
                Drag and drop an APK file here, or click to select
              </p>
              <p className="text-sm text-gray-500">Only .apk files are accepted</p>
            </div>
          )}
        </div>

        {loading && (
          <div className="mt-8 text-center">
            <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            <p className="mt-4 text-gray-600">Processing APK...</p>
          </div>
        )}

        {error && (
          <div className="mt-8 bg-red-50 border border-red-200 rounded-lg p-4">
            <p className="text-red-800">{error}</p>
          </div>
        )}

        {result && (
          <div className="mt-8 space-y-6">
            <div className="bg-white rounded-lg shadow-md p-6">
              <h2 className="text-2xl font-bold text-gray-900 mb-4">APK Information</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-gray-600">Package Name</p>
                  <p className="font-mono font-medium">{result.manifestInfo?.package || 'Unknown'}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Version</p>
                  <p className="font-mono font-medium">
                    {result.manifestInfo?.versionName || 'Unknown'} ({result.manifestInfo?.versionCode || 'Unknown'})
                  </p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Total Files</p>
                  <p className="font-medium">{result.fileCount}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Total Size</p>
                  <p className="font-medium">{(result.totalSize / 1024 / 1024).toFixed(2)} MB</p>
                </div>
              </div>
            </div>

            {result.manifestInfo?.permissions && result.manifestInfo.permissions.length > 0 && (
              <div className="bg-white rounded-lg shadow-md p-6">
                <h3 className="text-xl font-bold text-gray-900 mb-4">Permissions ({result.manifestInfo.permissions.length})</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {result.manifestInfo.permissions.map((perm, idx) => (
                    <div key={idx} className="text-sm font-mono bg-gray-50 p-2 rounded">
                      {perm.replace('android.permission.', '')}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {result.manifestInfo?.activities && result.manifestInfo.activities.length > 0 && (
              <div className="bg-white rounded-lg shadow-md p-6">
                <h3 className="text-xl font-bold text-gray-900 mb-4">Activities ({result.manifestInfo.activities.length})</h3>
                <div className="space-y-1">
                  {result.manifestInfo.activities.slice(0, 10).map((activity, idx) => (
                    <div key={idx} className="text-sm font-mono bg-gray-50 p-2 rounded">
                      {activity}
                    </div>
                  ))}
                  {result.manifestInfo.activities.length > 10 && (
                    <p className="text-sm text-gray-500 italic">
                      ...and {result.manifestInfo.activities.length - 10} more
                    </p>
                  )}
                </div>
              </div>
            )}

            <div className="bg-white rounded-lg shadow-md p-6">
              <h3 className="text-xl font-bold text-gray-900 mb-4">File Structure</h3>
              <div className="max-h-96 overflow-y-auto border border-gray-200 rounded p-4">
                <FileTree items={result.fileTree} extractId={result.extractId} />
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default App

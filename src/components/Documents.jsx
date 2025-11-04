import React, { useState, useEffect } from 'react'
import ReactMarkdown from 'react-markdown'

const DOCUMENTS = [
  { id: 'main', title: '📘 Main Documentation', file: 'MAIN.md' },
  { id: 'start', title: '🚀 Start Here', file: 'README_START_HERE.md' },
  { id: 'duffel', title: '🌐 Duffel Integration Analysis', file: 'DUFFEL_BOOKING_ANALYSIS.md' },
  { id: 'security', title: '🔒 Security Analysis', file: 'SECURITY_ANALYSIS_REPORT.md' },
  { id: 'api-guide', title: '⚡ API Exploitation Guide', file: 'API_EXPLOITATION_GUIDE.md' },
  { id: 'api-results', title: '📊 API Testing Results', file: 'API_TESTING_RESULTS.md' },
  { id: 'idor', title: '🔍 IDOR & Priority Findings', file: 'IDOR_AND_PRIORITY_FINDINGS.md' },
  { id: 'flights', title: '✈️ Available Flights', file: 'AVAILABLE_FLIGHTS.md' },
  { id: 'testing', title: '🧪 Testing Guide', file: 'TESTING_GUIDE_AND_NOTES.md' },
  { id: 'ldplayer', title: '🎮 LDPlayer Testing', file: 'COMPLETE_LDPLAYER_TESTING_SUITE.md' },
  { id: 'honest', title: '💯 Honest Assessment', file: 'HONEST_SECURITY_ASSESSMENT.md' },
  { id: 'reality', title: '🎯 Reality Check', file: 'REALITY_CHECK.md' },
  { id: 'summary', title: '📋 Executive Summary', file: 'FINAL_EXECUTIVE_SUMMARY.md' },
  { id: 'comprehensive', title: '📑 Comprehensive Results', file: 'FINAL_COMPREHENSIVE_RESULTS.md' },
]

function Documents() {
  const [selectedDoc, setSelectedDoc] = useState('duffel')
  const [content, setContent] = useState('')
  const [loading, setLoading] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')

  useEffect(() => {
    loadDocument(selectedDoc)
  }, [selectedDoc])

  const loadDocument = async (docId) => {
    setLoading(true)
    const doc = DOCUMENTS.find(d => d.id === docId)
    
    try {
      const response = await fetch(`/api/docs/${doc.file}`)
      const text = await response.text()
      setContent(text)
    } catch (err) {
      setContent(`# Error Loading Document\n\nFailed to load ${doc.file}`)
    } finally {
      setLoading(false)
    }
  }

  const filteredDocs = DOCUMENTS.filter(doc =>
    doc.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
    doc.file.toLowerCase().includes(searchTerm.toLowerCase())
  )

  return (
    <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
      <div className="lg:col-span-1">
        <div className="bg-white rounded-xl shadow-lg p-4 sticky top-4">
          <h3 className="text-lg font-bold text-gray-900 mb-4">📚 Knowledge Base</h3>
          
          <input
            type="text"
            placeholder="Search documents..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 rounded-lg mb-4 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          />

          <div className="space-y-1 max-h-[calc(100vh-250px)] overflow-y-auto">
            {filteredDocs.map(doc => (
              <button
                key={doc.id}
                onClick={() => setSelectedDoc(doc.id)}
                className={`w-full text-left px-3 py-2 rounded-lg transition-colors ${
                  selectedDoc === doc.id
                    ? 'bg-blue-600 text-white font-medium'
                    : 'text-gray-700 hover:bg-gray-100'
                }`}
              >
                <div className="text-sm">{doc.title}</div>
                <div className="text-xs opacity-75">{doc.file}</div>
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="lg:col-span-3">
        <div className="bg-white rounded-xl shadow-lg p-6">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <div className="w-8 h-8 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
            </div>
          ) : (
            <div className="prose prose-slate max-w-none">
              <ReactMarkdown
                components={{
                  h1: ({node, ...props}) => <h1 className="text-3xl font-bold text-gray-900 mb-4" {...props} />,
                  h2: ({node, ...props}) => <h2 className="text-2xl font-bold text-gray-900 mt-6 mb-3" {...props} />,
                  h3: ({node, ...props}) => <h3 className="text-xl font-bold text-gray-900 mt-4 mb-2" {...props} />,
                  p: ({node, ...props}) => <p className="text-gray-700 mb-4 leading-relaxed" {...props} />,
                  ul: ({node, ...props}) => <ul className="list-disc list-inside mb-4 space-y-1" {...props} />,
                  ol: ({node, ...props}) => <ol className="list-decimal list-inside mb-4 space-y-1" {...props} />,
                  li: ({node, ...props}) => <li className="text-gray-700" {...props} />,
                  code: ({node, inline, ...props}) => 
                    inline ? 
                      <code className="bg-gray-100 px-1.5 py-0.5 rounded text-sm font-mono text-red-600" {...props} /> :
                      <code className="block bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto font-mono text-sm" {...props} />,
                  pre: ({node, ...props}) => <pre className="mb-4 rounded-lg overflow-hidden" {...props} />,
                  blockquote: ({node, ...props}) => <blockquote className="border-l-4 border-blue-500 pl-4 italic text-gray-600 mb-4" {...props} />,
                  table: ({node, ...props}) => <div className="overflow-x-auto mb-4"><table className="min-w-full border border-gray-300" {...props} /></div>,
                  th: ({node, ...props}) => <th className="border border-gray-300 px-4 py-2 bg-gray-100 font-bold text-left" {...props} />,
                  td: ({node, ...props}) => <td className="border border-gray-300 px-4 py-2" {...props} />,
                }}
              >
                {content}
              </ReactMarkdown>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default Documents

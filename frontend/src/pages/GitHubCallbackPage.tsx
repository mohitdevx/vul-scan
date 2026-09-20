import React, { useEffect, useState } from 'react'
import { RiGithubFill, RiLoader4Line, RiCheckLine, RiAlertLine } from '@remixicon/react'
import { githubApi } from '../services/api'

interface GitHubCallbackPageProps {
  onDone?: () => void
}

export const GitHubCallbackPage: React.FC<GitHubCallbackPageProps> = ({ onDone }) => {
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading')
  const [errorMessage, setErrorMessage] = useState('')
  const [username, setUsername] = useState('')

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const code = params.get('code')
    const errorParam = params.get('error')
    const errorDesc = params.get('error_description')

    if (errorParam) {
      setStatus('error')
      setErrorMessage(errorDesc || errorParam || 'GitHub authorization was denied.')
      return
    }

    if (!code) {
      setStatus('error')
      setErrorMessage('No authorization code was found in the redirect.')
      return
    }

    githubApi
      .handleOAuthCallback(code)
      .then(res => {
        setStatus('success')
        setUsername(res.username)

        // If in a popup, message the parent window and close
        if (window.opener) {
          window.opener.postMessage(
            {
              type: 'GITHUB_AUTH_SUCCESS',
              username: res.username,
              avatarUrl: res.avatarUrl,
            },
            '*'
          )
          setTimeout(() => {
            window.close()
          }, 800)
        } else {
          setTimeout(() => {
            if (onDone) {
              onDone()
            } else {
              window.location.href = '/dashboard'
            }
          }, 1200)
        }
      })
      .catch(err => {
        setStatus('error')
        const msg = err instanceof Error ? err.message : 'Failed to complete GitHub authorization'
        setErrorMessage(msg)
      })
  }, [onDone])

  return (
    <div className="min-h-screen bg-[#09090b] text-zinc-100 flex flex-col items-center justify-center p-6">
      <div className="w-full max-w-md bg-[#121215] border border-[#27272a] rounded-2xl p-8 text-center space-y-6 shadow-2xl">
        <div className="w-14 h-14 rounded-2xl bg-zinc-900 border border-zinc-800 flex items-center justify-center mx-auto text-zinc-100">
          <RiGithubFill className="w-8 h-8" />
        </div>

        {status === 'loading' && (
          <div className="space-y-3">
            <div className="flex items-center justify-center gap-2 text-sm font-medium text-zinc-200">
              <RiLoader4Line className="w-4 h-4 animate-spin text-emerald-400" />
              <span>Connecting GitHub Authorization...</span>
            </div>
            <p className="text-xs text-zinc-500 font-sans">
              Exchanging secure authorization code with GitHub. Please wait a moment.
            </p>
          </div>
        )}

        {status === 'success' && (
          <div className="space-y-3">
            <div className="w-10 h-10 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center mx-auto">
              <RiCheckLine className="w-5 h-5" />
            </div>
            <h2 className="text-base font-semibold text-zinc-100">Successfully Authorized!</h2>
            <p className="text-xs text-zinc-400">
              Connected as <strong className="text-zinc-200">@{username}</strong>. You can now create Pull Requests with 1-click.
            </p>
            <p className="text-[11px] text-zinc-500">Closing window automatically...</p>
          </div>
        )}

        {status === 'error' && (
          <div className="space-y-3">
            <div className="w-10 h-10 rounded-full bg-rose-500/10 border border-rose-500/20 text-rose-400 flex items-center justify-center mx-auto">
              <RiAlertLine className="w-5 h-5" />
            </div>
            <h2 className="text-base font-semibold text-zinc-100">Authorization Failed</h2>
            <p className="text-xs text-rose-300 font-sans">{errorMessage}</p>
            <div className="pt-2">
              <button
                type="button"
                onClick={() => (window.opener ? window.close() : (window.location.href = '/dashboard'))}
                className="px-4 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs rounded-lg cursor-pointer"
              >
                {window.opener ? 'Close Window' : 'Return to Dashboard'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

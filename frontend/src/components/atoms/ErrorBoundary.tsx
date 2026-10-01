import { Component, type ErrorInfo, type ReactNode } from 'react'
import { RiAlertLine, RiRefreshLine } from '@remixicon/react'
import { Button } from './Button'

interface Props {
  children: ReactNode
  fallbackTitle?: string
}

interface State {
  hasError: boolean
  error: Error | null
  errorInfo: ErrorInfo | null
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
  }

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null }
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error in React component tree:', error, errorInfo)
    this.setState({ errorInfo })
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null })
    window.location.reload()
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-[400px] flex flex-col items-center justify-center p-6 text-center space-y-4">
          <div className="p-6 rounded-lg bg-surface border border-border-subtle max-w-lg w-full space-y-3 font-mono text-xs text-left">
            <div className="flex items-center gap-2 text-rose-400 font-semibold text-sm">
              <RiAlertLine className="w-4 h-4 shrink-0" />
              <span>{this.props.fallbackTitle || 'Component Rendering Error'}</span>
            </div>
            <p className="text-text-secondary">
              An unexpected error occurred while rendering this view.
            </p>
            {this.state.error && (
              <div className="p-2.5 rounded bg-canvas border border-border-subtle text-rose-300 font-mono text-[11px] overflow-x-auto">
                {this.state.error.message || String(this.state.error)}
              </div>
            )}
            <div className="flex items-center gap-2 pt-2">
              <Button
                variant="secondary"
                size="sm"
                onClick={this.handleReset}
                className="flex items-center gap-1.5 text-xs font-mono"
              >
                <RiRefreshLine className="w-3.5 h-3.5" />
                <span>Reload Page</span>
              </Button>
            </div>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}

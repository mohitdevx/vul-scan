import { forwardRef } from 'react'
import { Input, type InputProps } from '../atoms/Input'

export interface FormFieldProps extends InputProps {
  label: string
  error?: string
  helperText?: string
  required?: boolean
}

export const FormField = forwardRef<HTMLInputElement, FormFieldProps>(
  ({ label, error, helperText, required, id, ...inputProps }, ref) => {
    const inputId = id || label.toLowerCase().replace(/\s+/g, '-')

    return (
      <div className="w-full flex flex-col gap-1.5 text-left">
        <label
          htmlFor={inputId}
          className="text-xs font-medium text-zinc-300 flex items-center justify-between"
        >
          <span>
            {label}
            {required && <span className="text-zinc-500 ml-1">*</span>}
          </span>
        </label>
        <Input
          ref={ref}
          id={inputId}
          hasError={Boolean(error)}
          aria-invalid={Boolean(error)}
          {...inputProps}
        />
        {error ? (
          <span className="text-xs text-red-400">{error}</span>
        ) : helperText ? (
          <span className="text-xs text-zinc-500">{helperText}</span>
        ) : null}
      </div>
    )
  }
)

FormField.displayName = 'FormField'

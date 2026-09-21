import { useState, useEffect, type FC } from 'react'
import {
  RiCloseLine,
  RiMailLine,
  RiUserLine,
  RiBuildingLine,
  RiShieldCheckLine,
} from '@remixicon/react'
import { Button } from '../atoms/Button'
import { FormField } from '../molecules/FormField'
import { useAuth } from '../../context/AuthContext'
import { useToast } from '../../context/ToastContext'

export interface ProfileModalProps {
  isOpen: boolean
  onClose: () => void
}

export const ProfileModal: FC<ProfileModalProps> = ({ isOpen, onClose }) => {
  const { user } = useAuth()
  const { info } = useToast()

  const [firstName, setFirstName] = useState('')
  const [lastName, setLastName] = useState('')
  const [orgName, setOrgName] = useState('')
  const [email, setEmail] = useState('')

  useEffect(() => {
    if (user) {
      setFirstName(user.firstName || '')
      setLastName(user.lastName || '')
      setOrgName(user.orgName || '')
      setEmail(user.email || '')
    }
  }, [user, isOpen])

  if (!isOpen || !user) return null

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault()
    info('Profile details are synced with your active session.', 'Profile Saved')
    onClose()
  }

  const initials = `${user.firstName?.charAt(0) || ''}${user.lastName?.charAt(0) || ''}`.toUpperCase() || 'U'

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6"
    >
      {/* Backdrop */}
      <div
        onClick={onClose}
        className="fixed inset-0 bg-black/80 backdrop-blur-sm transition-opacity duration-150"
      />

      {/* Modal Container */}
      <div className="relative w-full max-w-[440px] bg-surface border border-border rounded-2xl shadow-2xl z-10 p-6 sm:p-7 text-left">
        {/* Header */}
        <div className="flex items-start justify-between pb-4 border-b border-border mb-5">
          <div className="flex items-center gap-3">
            <div className="w-11 h-11 rounded-full bg-surface-muted border border-border flex items-center justify-center text-text-primary text-sm font-semibold tracking-wider">
              {initials}
            </div>
            <div>
              <h2 className="text-sm font-semibold text-text-primary tracking-tight">
                Account Profile
              </h2>
              <p className="text-xs text-text-muted mt-0.5 font-mono">
                {user.email}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close profile"
            className="text-text-muted hover:text-text-primary p-1 rounded-md hover:bg-surface-hover transition-colors cursor-pointer"
          >
            <RiCloseLine className="w-4 h-4" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSave} className="flex flex-col gap-3.5">
          <div className="grid grid-cols-2 gap-3">
            <FormField
              label="First Name"
              placeholder="First name"
              value={firstName}
              onChange={e => setFirstName(e.target.value)}
              icon={<RiUserLine className="w-3.5 h-3.5" />}
            />
            <FormField
              label="Last Name"
              placeholder="Last name"
              value={lastName}
              onChange={e => setLastName(e.target.value)}
              icon={<RiUserLine className="w-3.5 h-3.5" />}
            />
          </div>

          <FormField
            label="Organization"
            placeholder="Organization"
            value={orgName}
            onChange={e => setOrgName(e.target.value)}
            icon={<RiBuildingLine className="w-3.5 h-3.5" />}
          />

          <FormField
            label="Email Address"
            type="email"
            disabled
            value={email}
            onChange={() => {}}
            icon={<RiMailLine className="w-3.5 h-3.5" />}
          />

          <div className="p-3 rounded-xl bg-surface-muted/60 border border-border-subtle flex items-start gap-2.5 text-xs text-text-secondary mt-1">
            <RiShieldCheckLine className="w-4 h-4 text-text-muted shrink-0 mt-0.5" />
            <span className="leading-relaxed">
              Authenticated SAST session active. Changes apply to newly generated report IRs.
            </span>
          </div>

          {/* Footer Actions */}
          <div className="pt-3 flex items-center justify-end gap-2.5">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={onClose}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="primary"
              size="sm"
            >
              Done
            </Button>
          </div>
        </form>
      </div>
    </div>
  )
}

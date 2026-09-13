import type { Request, Response, NextFunction } from 'express'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { z } from 'zod'
import { prisma } from '../config/db.js'
import { config } from '../config/env.js'

export const signupSchema = z
  .object({
    firstname: z.string().min(1, 'First name is required').optional(),
    firstName: z.string().min(1, 'First name is required').optional(),
    lastname: z.string().min(1, 'Last name is required').optional(),
    lastName: z.string().min(1, 'Last name is required').optional(),
    org_name: z.string().min(1, 'Organization name is required').optional(),
    orgName: z.string().min(1, 'Organization name is required').optional(),
    email: z.string().email('Invalid email address'),
    password: z.string().min(6, 'Password must be at least 6 characters long'),
    confirmPassword: z.string().min(1, 'Please confirm your password').optional(),
    confirm_password: z.string().min(1, 'Please confirm your password').optional(),
  })
  .refine(
    data => {
      const p1 = data.password
      const p2 = data.confirmPassword || data.confirm_password
      return !p2 || p1 === p2
    },
    {
      message: "Passwords don't match",
      path: ['confirmPassword'],
    }
  )

export const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
})

export async function signup(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const validated = signupSchema.parse(req.body)

    const firstName = validated.firstname || validated.firstName
    const lastName = validated.lastname || validated.lastName
    const orgName = validated.org_name || validated.orgName
    const email = validated.email.toLowerCase().trim()
    const password = validated.password

    if (!firstName || !lastName || !orgName) {
      res.status(400).json({
        error: 'Validation failed',
        message: 'First name, last name, and organization name are required',
      })
      return
    }

    const existingUser = await prisma.user.findUnique({
      where: { email },
    })

    if (existingUser) {
      res.status(409).json({
        error: 'Conflict',
        message: 'An account with this email already exists',
      })
      return
    }

    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)

    const user = await prisma.user.create({
      data: {
        firstName,
        lastName,
        orgName,
        email,
        password: hashedPassword,
      },
      select: {
        id: true,
        firstName: true,
        lastName: true,
        orgName: true,
        email: true,
        createdAt: true,
      },
    })

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        orgName: user.orgName,
      },
      config.jwtSecret,
      { expiresIn: '7d' }
    )

    res.cookie('token', token, {
      httpOnly: true,
      secure: config.nodeEnv === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    })

    res.status(201).json({
      message: 'Account created successfully',
      token,
      user,
    })
  } catch (error) {
    if (error instanceof z.ZodError) {
      res.status(400).json({
        error: 'Validation Error',
        message: error.errors[0]?.message || 'Invalid input data',
        issues: error.errors,
      })
      return
    }
    next(error)
  }
}

export async function login(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const validated = loginSchema.parse(req.body)
    const email = validated.email.toLowerCase().trim()

    const user = await prisma.user.findUnique({
      where: { email },
    })

    if (!user) {
      res.status(401).json({
        error: 'Authentication failed',
        message: 'Invalid email or password',
      })
      return
    }

    const isMatch = await bcrypt.compare(validated.password, user.password)
    if (!isMatch) {
      res.status(401).json({
        error: 'Authentication failed',
        message: 'Invalid email or password',
      })
      return
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        orgName: user.orgName,
      },
      config.jwtSecret,
      { expiresIn: '7d' }
    )

    res.cookie('token', token, {
      httpOnly: true,
      secure: config.nodeEnv === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    })

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        orgName: user.orgName,
        email: user.email,
        createdAt: user.createdAt,
      },
    })
  } catch (error) {
    if (error instanceof z.ZodError) {
      res.status(400).json({
        error: 'Validation Error',
        message: error.errors[0]?.message || 'Invalid input data',
      })
      return
    }
    next(error)
  }
}

export async function getMe(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    // Extracted from auth middleware
    const userId = (req as any).user?.id
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized', message: 'Not authenticated' })
      return
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        firstName: true,
        lastName: true,
        orgName: true,
        email: true,
        createdAt: true,
      },
    })

    if (!user) {
      res.status(404).json({ error: 'Not found', message: 'User not found' })
      return
    }

    res.json({ user })
  } catch (error) {
    next(error)
  }
}

export function logout(_req: Request, res: Response): void {
  res.clearCookie('token')
  res.json({ message: 'Logged out successfully' })
}

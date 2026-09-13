import { Router } from 'express'
import { getScanStatus, triggerScan } from '../controllers/scan.controller.js'

export const scanRouter = Router()

scanRouter.post('/', triggerScan)
scanRouter.get('/:id', getScanStatus)

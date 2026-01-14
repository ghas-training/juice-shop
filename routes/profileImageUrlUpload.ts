/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import net from 'node:net'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isUrlAllowed (urlString: string): boolean {
  let parsed: URL
  try {
    parsed = new URL(urlString)
  } catch {
    return false
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return false
  }

  const hostname = parsed.hostname.toLowerCase()

  if (hostname === 'localhost') {
    return false
  }

  const ipType = net.isIP(hostname)
  if (ipType !== 0) {
    // IPv4
    if (ipType === 4) {
      const octets = hostname.split('.').map(Number)
      if (octets.length === 4) {
        const [o1, o2] = octets
        // 127.0.0.0/8 loopback
        if (o1 === 127) return false
        // 10.0.0.0/8 private
        if (o1 === 10) return false
        // 172.16.0.0/12 private
        if (o1 === 172 && o2 >= 16 && o2 <= 31) return false
        // 192.168.0.0/16 private
        if (o1 === 192 && o2 === 168) return false
      }
    }
    // Treat all IPv6 literals as disallowed to avoid local/unique scopes
    if (ipType === 6) {
      return false
    }
  }

  return true
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          if (!isUrlAllowed(url)) {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Blocked SSRF attempt for profile image URL "${url}"; using image link directly`)
          } else {
            const response = await fetch(url)
            if (!response.ok || !response.body) {
              throw new Error('url returned a non-OK status code or an empty body')
            }
            const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
            const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
            await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
            await UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
          }
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}

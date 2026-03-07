/**
 * OAuth.do test setup
 */

import { beforeEach, afterAll } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// Add jest-dom matchers for React testing
import '@testing-library/jest-dom'

const tempHome = mkdtempSync(join(tmpdir(), 'oauth-do-tests-'))
const originalHome = process.env.HOME
const originalConfigHome = process.env.XDG_CONFIG_HOME

process.env.HOME = tempHome
process.env.XDG_CONFIG_HOME = join(tempHome, '.config')

beforeEach(() => {
  rmSync(join(tempHome, '.id.org.ai'), { recursive: true, force: true })
  rmSync(join(tempHome, '.oauth.do'), { recursive: true, force: true })
  rmSync(join(tempHome, '.test-oauth'), { recursive: true, force: true })
})

afterAll(() => {
  if (originalHome === undefined) {
    delete process.env.HOME
  } else {
    process.env.HOME = originalHome
  }

  if (originalConfigHome === undefined) {
    delete process.env.XDG_CONFIG_HOME
  } else {
    process.env.XDG_CONFIG_HOME = originalConfigHome
  }

  rmSync(tempHome, { recursive: true, force: true })
})

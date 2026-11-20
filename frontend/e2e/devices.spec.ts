import { execFileSync, spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

import { expect, test, type Page } from '@playwright/test'

const win = process.platform === 'win32'
const python = resolve(process.env.E2E_PYTHON ?? (win ? '../backend/.venv/Scripts/python.exe' : '../backend/.venv/bin/python'))
const agentDir = resolve('../agent')

function agentEnv(home: string) {
  const local = '127.0.0.1,localhost'
  return { ...process.env, PYTHONPATH: agentDir, SENTINEL_AGENT_HOME: home, NO_PROXY: local, no_proxy: local }
}

async function signUpWithOrg(page: Page, org: string) {
  await page.goto('/register')
  await page.getByLabel('Full name').fill('Device Admin')
  await page.getByLabel('Work email').fill(`devices-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`)
  await page.getByLabel('Password', { exact: true }).fill('Blue-Team-Lab-2026!')
  await page.getByRole('button', { name: 'Create account' }).click()
  await page.getByLabel('Organization name').fill(org)
  await page.getByRole('button', { name: 'Create organization' }).click()
  await expect(page).toHaveURL(/\/org\/[0-9a-f-]{36}$/)
  return page.url()
}

test('enroll the real agent from the console, see it live, then revoke it', async ({ page }) => {
  const home = mkdtempSync(join(tmpdir(), 'sx-agent-'))
  try {
    const orgUrl = await signUpWithOrg(page, 'Agent Lab')
    await expect(page.getByRole('status').filter({ hasText: 'Live' })).toBeVisible()

    await page.goto(`${orgUrl}/devices`)
    await page.getByRole('button', { name: 'Enroll your first device' }).click()
    await page.getByLabel('Label').fill('E2E workstations')
    await page.getByRole('button', { name: 'Create token' }).click()
    const command = await page.locator('pre', { hasText: 'sentinel-agent enroll' }).innerText()
    await page.getByRole('button', { name: 'Done' }).click()

    // Exactly what the console told the user to run.
    const args = command.trim().split(/\s+/).slice(1)
    execFileSync(python, ['-m', 'sentinel_agent', ...args, '--name', 'e2e-laptop'], { env: agentEnv(home) })
    execFileSync(python, ['-m', 'sentinel_agent', 'run', '--once'], { env: agentEnv(home) })

    // Pushed over the WebSocket: no reload needed.
    const row = page.getByRole('row', { name: /Open e2e-laptop/ })
    await expect(row).toBeVisible()
    await expect(row).toContainText(/Online|Degraded/)

    await row.click()
    await expect(page.getByText(/Listening TCP ports/)).toBeVisible()
    page.once('dialog', (d) => void d.accept())
    await page.getByRole('button', { name: 'Revoke device' }).click()
    await expect(page.getByText('This device was revoked')).toBeVisible()

    // The agent's credential is now dead: it exits with code 3 instead of retrying forever.
    const run = spawnSync(python, ['-m', 'sentinel_agent', 'run'], { env: agentEnv(home), timeout: 30_000 })
    expect(run.status).toBe(3)
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})

test('a high-severity report raises an alert, a live toast and a notification', async ({ page }) => {
  const orgUrl = await signUpWithOrg(page, 'Event Lab')
  await page.goto(`${orgUrl}/events`)
  await expect(page.getByText('Streaming live')).toBeVisible()
  await page.getByRole('button', { name: 'Report event' }).click()
  const dialog = page.getByRole('dialog', { name: 'Report a security event' })
  await dialog.getByLabel('Title', { exact: true }).fill('Unknown USB device in server room')
  await dialog.getByLabel('Severity').selectOption('high')
  await dialog.getByRole('button', { name: 'Submit event' }).click()

  await expect(page.getByRole('region', { name: 'Live alerts' }).getByText('High alert')).toBeVisible()
  await expect(page.getByRole('row', { name: /Unknown USB device/ })).toBeVisible()
  await expect(page.getByText('Open alerts')).toBeVisible()
  await expect(page.getByRole('button', { name: /Notifications, 1 unread/ })).toBeVisible()
})

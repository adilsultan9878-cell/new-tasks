import { readFileSync } from 'node:fs'

import { expect, test, type Page } from '@playwright/test'

async function signUpWithOrg(page: Page, org: string) {
  await page.goto('/register')
  await page.getByLabel('Full name').fill('Brain Analyst')
  await page.getByLabel('Work email').fill(`brain-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`)
  await page.getByLabel('Password', { exact: true }).fill('Blue-Team-Lab-2026!')
  await page.getByRole('button', { name: 'Create account' }).click()
  await page.getByLabel('Organization name').fill(org)
  await page.getByRole('button', { name: 'Create organization' }).click()
  await expect(page).toHaveURL(/\/org\/[0-9a-f-]{36}$/)
  return page.url()
}

test('a new alert is triaged automatically and explained without AI', async ({ page }) => {
  const orgUrl = await signUpWithOrg(page, 'Brain Lab')
  await page.goto(`${orgUrl}/events`)
  await page.getByRole('button', { name: 'Report event' }).click()
  const dialog = page.getByRole('dialog', { name: 'Report a security event' })
  await dialog.getByLabel('Title', { exact: true }).fill('Ransomware note found on file share')
  await dialog.getByLabel('Severity').selectOption('critical')
  await dialog.getByRole('button', { name: 'Submit event' }).click()

  // critical severity = 50/50 points; no device, so device and exposure factors have no data.
  const triage = page.getByRole('link', { name: /P2/ })
  await expect(triage).toBeVisible()
  await triage.click()
  await expect(page).toHaveURL(/\/brain\/runs\/[0-9a-f-]{36}$/)
  await expect(page.getByRole('heading', { name: 'Ransomware note found on file share' })).toBeVisible()
  await expect(page.getByText(/no AI model/)).toBeVisible()
  await expect(page.getByRole('meter', { name: 'Risk score' })).toHaveAttribute('aria-valuenow', '50')
  await expect(page.getByText(/no data · \/10/).first()).toBeVisible()
  await expect(page.getByText('Automatic triage when the alert was raised', { exact: false })).toBeVisible()
})

test('organization analysis, report download and the agent center', async ({ page }) => {
  const orgUrl = await signUpWithOrg(page, 'Posture Lab')
  await page.goto(`${orgUrl}/brain`)
  await expect(page.getByText('No analyses yet')).toBeVisible()
  await expect(page.getByText('AI provider: none')).toBeVisible()
  await page.getByRole('button', { name: 'Analyze organization' }).click()

  await expect(page).toHaveURL(/\/brain\/runs\/[0-9a-f-]{36}$/)
  await expect(page.getByRole('heading', { name: 'Posture Lab' })).toBeVisible()
  await expect(page.getByText(/Data coverage/)).toContainText('40%') // honest about missing data
  await expect(page.getByText(/Enroll devices with the local agent/)).toBeVisible()

  const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Report (.md)' }).click()])
  expect(download.suggestedFilename()).toMatch(/^sentinel-x-organization-posture-lab-.*\.md$/)
  const report = readFileSync((await download.path())!, 'utf8')
  expect(report).toContain('# Organization posture: Posture Lab')
  expect(report).toContain('no AI model')

  await page.goto(`${orgUrl}/agents`)
  await expect(page.getByRole('heading', { name: 'Alert Triage Agent' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Security Posture Agent' })).toBeVisible()
  await expect(page.getByText('No enrolled devices')).toBeVisible() // decision history
})

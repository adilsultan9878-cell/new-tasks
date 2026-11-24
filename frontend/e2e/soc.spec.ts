import { expect, test, type Page } from '@playwright/test'

async function signUpWithOrg(page: Page, org: string) {
  await page.goto('/register')
  await page.getByLabel('Full name').fill('Sara Responder')
  await page.getByLabel('Work email').fill(`soc-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`)
  await page.getByLabel('Password', { exact: true }).fill('Blue-Team-Lab-2026!')
  await page.getByRole('button', { name: 'Create account' }).click()
  await page.getByLabel('Organization name').fill(org)
  await page.getByRole('button', { name: 'Create organization' }).click()
  await expect(page).toHaveURL(/\/org\/[0-9a-f-]{36}$/)
  return page.url()
}

test('alert → incident → approved block action → evidence → report', async ({ page }) => {
  const orgUrl = await signUpWithOrg(page, 'SOC Lab')
  await page.goto(`${orgUrl}/events`)
  await page.getByRole('button', { name: 'Report event' }).click()
  const report = page.getByRole('dialog', { name: 'Report a security event' })
  await report.getByLabel('Title', { exact: true }).fill('Beaconing to 203.0.113.66 from the finance PC')
  await report.getByLabel('Severity').selectOption('critical')
  await report.getByRole('button', { name: 'Submit event' }).click()
  await expect(report).toBeHidden()

  await page.getByRole('button', { name: 'Open incident' }).click()
  const dialog = page.getByRole('dialog', { name: 'New incident' })
  await expect(dialog.getByLabel('Title')).toHaveValue('Beaconing to 203.0.113.66 from the finance PC')
  await dialog.getByRole('button', { name: 'Open incident' }).click()
  await expect(page).toHaveURL(/\/incidents\/[0-9a-f-]{36}$/)
  await expect(page.getByText(/INC-\d{4}-0001/)).toBeVisible()

  // Medium impact: it waits for an approver; the sole approver may approve it.
  await page.getByRole('button', { name: 'Propose action' }).click()
  const propose = page.getByRole('dialog', { name: 'Propose a response action' })
  await propose.getByLabel('Action').selectOption('block_indicator')
  await propose.getByLabel('Value').fill('203.0.113.66')
  await propose.getByLabel('Reason').fill('C2 beacon from the finance PC')
  await propose.getByRole('button', { name: 'Request approval' }).click()
  await expect(page.getByText('Waiting for approval')).toBeVisible()
  await page.getByRole('button', { name: 'Approve' }).click()
  await expect(page.getByText('Done', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Roll back' })).toBeVisible()

  await page.getByRole('button', { name: 'Add evidence' }).click()
  const evidence = page.getByRole('dialog', { name: 'Add evidence' })
  await evidence.getByRole('tab', { name: 'Note' }).click()
  await evidence.getByLabel('Title').fill('Analyst interview')
  await evidence.getByLabel('Note').fill('User opened the invoice attachment at 09:12.')
  await evidence.getByRole('button', { name: 'Store evidence' }).click()
  await expect(page.getByTitle('SHA-256')).toHaveText(/[0-9a-f]{64}/)
  await page.getByRole('button', { name: 'Verify hash' }).click()
  await expect(page.getByText('Intact — hash matches')).toBeVisible()

  await page.getByRole('list', { name: 'Incident status' }).getByRole('button', { name: 'Contained' }).click()
  await expect(page.getByRole('list', { name: 'Incident status' }).getByRole('button', { name: 'Contained' })).toHaveAttribute('aria-current', 'step')

  await page.getByRole('button', { name: 'Generate report' }).click()
  await expect(page).toHaveURL(/\/reports\/[0-9a-f-]{36}$/)
  await expect(page.getByText(/Incident report — INC-\d{4}-0001/).first()).toBeVisible()
  await expect(page.getByText(/Add to block list|Block ipv4 203\.0\.113\.66/).first()).toBeVisible()
})

test('the emergency stop holds every action', async ({ page }) => {
  const orgUrl = await signUpWithOrg(page, 'Stop Lab')
  await page.goto(`${orgUrl}/incidents`)
  await page.getByRole('button', { name: 'Emergency stop' }).click()
  const dialog = page.getByRole('dialog', { name: 'Engage the emergency stop?' })
  await dialog.getByLabel('Reason').fill('Tabletop drill')
  await dialog.getByRole('button', { name: 'Engage stop' }).click()
  await expect(page.getByText('Emergency stop engaged — no response action can run')).toBeVisible()

  await page.getByRole('button', { name: 'Propose action' }).click()
  const propose = page.getByRole('dialog', { name: 'Propose a response action' })
  await propose.getByLabel('Message').fill('Join the bridge call now')
  await propose.getByRole('button', { name: 'Run action' }).click()
  await expect(page.getByText(/Emergency stop is engaged — run it after/).first()).toBeVisible()

  await page.getByRole('button', { name: 'Release emergency stop' }).click()
  await page.getByRole('dialog', { name: 'Release the emergency stop?' }).getByRole('button', { name: 'Release' }).click()
  await expect(page.getByText('Emergency stop engaged — no response action can run')).toHaveCount(0)
  await page.getByRole('button', { name: 'Run now' }).first().click()
  await expect(page.getByText('Done', { exact: true }).first()).toBeVisible()
})

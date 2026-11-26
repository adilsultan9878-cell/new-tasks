import { expect, test, type Page } from '@playwright/test'

async function signUpWithOrg(page: Page, org: string) {
  await page.goto('/register')
  await page.getByLabel('Full name').fill('Owner Person')
  await page.getByLabel('Work email').fill(`owner-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`)
  await page.getByLabel('Password', { exact: true }).fill('Blue-Team-Lab-2026!')
  await page.getByRole('button', { name: 'Create account' }).click()
  await page.getByLabel('Organization name').fill(org)
  await page.getByRole('button', { name: 'Create organization' }).click()
  await expect(page).toHaveURL(/\/org\/[0-9a-f-]{36}$/)
  return page.url()
}

test('invite a colleague by e-mail; they create an account from the link and land in the organization', async ({ page, browser }) => {
  const orgUrl = await signUpWithOrg(page, 'Invite Lab')
  await page.goto(`${orgUrl}/members`)
  await page.getByRole('button', { name: 'Invite by e-mail' }).click()
  const dialog = page.getByRole('dialog', { name: 'Invite by e-mail' })
  const email = `colleague-${Date.now()}@example.com`
  await dialog.getByLabel('Email').fill(email)
  await dialog.getByLabel('Role').selectOption('analyst')
  await dialog.getByRole('button', { name: 'Send invitation' }).click()
  // The e2e server has no e-mail provider: the link is shown once to pass on by hand.
  await expect(dialog.getByText(/E-mail is not set up on this server/)).toBeVisible()
  const link = ((await dialog.locator('pre').textContent()) ?? '').trim()
  expect(link).toMatch(/\/invite#token=[A-Za-z0-9_-]{20,}$/)
  await dialog.getByRole('button', { name: 'Done' }).click()
  await expect(page.getByText(email)).toBeVisible()

  // The colleague, in a separate browser.
  const other = await browser.newContext()
  const guest = await other.newPage()
  await guest.goto(link.replace(/^https?:\/\/[^/]+/, ''))
  await expect(guest.getByText('Invite Lab')).toBeVisible()
  await expect(guest.getByText(/as Security Analyst/)).toBeVisible()
  await guest.getByLabel('Full name').fill('Colleague Analyst')
  await guest.getByLabel('Password', { exact: true }).fill('Another-Strong-Passphrase-77')
  await guest.getByRole('button', { name: 'Create account and join' }).click()
  await expect(guest).toHaveURL(/\/org\/[0-9a-f-]{36}$/)
  await expect(guest.getByText('Invite Lab').first()).toBeVisible()

  // The link worked once; the owner sees a new analyst and no pending invitation.
  await guest.goto(link.replace(/^https?:\/\/[^/]+/, ''))
  await expect(guest.getByText(/This invitation is no longer valid/)).toBeVisible()
  await page.reload()
  await expect(page.getByRole('cell', { name: /Colleague Analyst/ })).toBeVisible()
  await expect(page.getByText(/Invitations \(/)).toHaveCount(0)
  await other.close()
})

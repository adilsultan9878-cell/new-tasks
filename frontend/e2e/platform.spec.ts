import { expect, test, type Page } from '@playwright/test'

const PASSWORD = 'Blue-Team-Lab-2026!'
const unique = (name: string) => `${name}-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`

async function register(page: Page, fullName: string, email: string) {
  await page.goto('/register')
  await page.getByLabel('Full name').fill(fullName)
  await page.getByLabel('Work email').fill(email)
  await page.getByLabel('Password', { exact: true }).fill(PASSWORD)
  await page.getByRole('button', { name: 'Create account' }).click()
  await expect(page).toHaveURL(/\/onboarding$/)
}

async function createOrg(page: Page, name: string): Promise<string> {
  await page.getByLabel('Organization name').fill(name)
  await page.getByRole('button', { name: 'Create organization' }).click()
  await expect(page).toHaveURL(/\/org\/[0-9a-f-]{36}$/)
  await expect(page.getByRole('heading', { name })).toBeVisible()
  return page.url()
}

async function signOut(page: Page) {
  await page.getByRole('button', { name: 'Account menu' }).click()
  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page).toHaveURL(/\/login$/)
}

test('register → create organization → dashboard → session survives reload → sign out → sign in', async ({ page }) => {
  const email = unique('owner')
  await register(page, 'Ayesha Khan', email)
  const orgUrl = await createOrg(page, 'Karachi Cyber Research Lab')

  // Real, empty metrics — not fake counters.
  await expect(page.getByTestId('kpi-Enrolled devices')).toHaveText('0')
  await expect(page.getByTestId('kpi-Critical alerts')).toHaveText('0')
  await expect(page.getByText('No enrolled devices')).toBeVisible()

  // Access token lives in memory; reload restores the session from the HttpOnly refresh cookie.
  await page.reload()
  await expect(page.getByRole('heading', { name: 'Karachi Cyber Research Lab' })).toBeVisible()

  // The creation was audited.
  await page.goto(`${orgUrl}/audit`)
  await expect(page.getByRole('cell', { name: 'org.create' })).toBeVisible()

  await signOut(page)
  await page.goto(orgUrl)
  await expect(page).toHaveURL(/\/login$/)

  await page.getByLabel('Work email').fill(email)
  await page.getByLabel('Password', { exact: true }).fill(PASSWORD)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).toHaveURL(orgUrl)
})

test('wrong password shows a generic error', async ({ page }) => {
  await page.goto('/login')
  await page.getByLabel('Work email').fill(unique('nobody'))
  await page.getByLabel('Password', { exact: true }).fill('definitely-wrong-password')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('alert')).toContainText('Invalid email or password')
})

test('tenant isolation and RBAC in the UI', async ({ browser }) => {
  const ownerCtx = await browser.newContext()
  const viewerCtx = await browser.newContext()
  const owner = await ownerCtx.newPage()
  const viewer = await viewerCtx.newPage()

  const viewerEmail = unique('viewer')
  await register(viewer, 'Bilal Viewer', viewerEmail)
  await register(owner, 'Olivia Owner', unique('owner'))
  const orgUrl = await createOrg(owner, 'Isolated Org')

  // Not a member yet: the organization is simply not available.
  await viewer.goto(orgUrl)
  await expect(viewer.getByText('Organization not available')).toBeVisible()

  // Owner adds the viewer with the read-only role.
  await owner.goto(`${orgUrl}/members`)
  await owner.getByRole('button', { name: 'Add member' }).click()
  await owner.getByLabel('Email').fill(viewerEmail)
  await owner.getByLabel('Role').selectOption('viewer')
  await owner.getByRole('dialog').getByRole('button', { name: 'Add member' }).click()
  await expect(owner.getByRole('cell', { name: /Bilal Viewer/ })).toBeVisible()

  // Viewer now sees the org, but read-only.
  await viewer.goto(orgUrl)
  await expect(viewer.getByRole('heading', { name: 'Isolated Org' })).toBeVisible()
  await viewer.goto(`${orgUrl}/members`)
  await expect(viewer.getByRole('cell', { name: /Olivia Owner/ })).toBeVisible()
  await expect(viewer.getByRole('button', { name: 'Add member' })).toHaveCount(0)
  await viewer.goto(`${orgUrl}/organization`)
  await expect(viewer.getByLabel('Name')).toBeDisabled()

  // The membership notification reached the viewer.
  await viewer.getByRole('button', { name: /Notifications, 1 unread/ }).click()
  await expect(viewer.getByText('You were added to Isolated Org')).toBeVisible()

  await ownerCtx.close()
  await viewerCtx.close()
})

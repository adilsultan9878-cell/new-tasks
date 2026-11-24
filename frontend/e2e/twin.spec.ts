import { expect, test, type Page } from '@playwright/test'

async function signUpWithOrg(page: Page, org: string) {
  await page.goto('/register')
  await page.getByLabel('Full name').fill('Twin Builder')
  await page.getByLabel('Work email').fill(`twin-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`)
  await page.getByLabel('Password', { exact: true }).fill('Blue-Team-Lab-2026!')
  await page.getByRole('button', { name: 'Create account' }).click()
  await page.getByLabel('Organization name').fill(org)
  await page.getByRole('button', { name: 'Create organization' }).click()
  await expect(page).toHaveURL(/\/org\/[0-9a-f-]{36}$/)
  return page.url()
}

test('the digital twin renders the site in 3D, lists it by room and saves a new room', async ({ page }) => {
  const orgUrl = await signUpWithOrg(page, 'Twin Lab')
  await page.goto(`${orgUrl}/twin`)
  await expect(page.getByText('Nothing on the map yet')).toBeVisible()
  await page.getByRole('button', { name: 'Try the simulator' }).first().click()

  await expect(page.getByTestId('twin-canvas')).toHaveAttribute('data-ready', 'true', { timeout: 15_000 })
  await expect(page.getByText('4 of 4 placed')).toBeVisible()
  await expect(page.getByText('How to read the map')).toBeVisible()

  await page.getByRole('tab', { name: 'List' }).click()
  const room = page.getByRole('region', { name: 'Server room' })
  await expect(room.getByText('sim-db-01')).toBeVisible()
  await room.getByRole('button', { name: /sim-db-01/ }).click()
  await expect(page.getByText('In Server room')).toBeVisible()

  await page.getByRole('button', { name: 'Edit layout' }).click()
  await expect(page.getByRole('button', { name: 'Save layout' })).toBeDisabled()
  await page.getByLabel('Room name').fill('Loading bay')
  await page.getByLabel('Room x').fill('60')
  await page.getByLabel('Room y').fill('38')
  await page.getByRole('button', { name: 'Add room' }).click()
  await page.getByRole('button', { name: 'Save layout' }).click()
  await expect(page.getByRole('button', { name: 'Edit layout' })).toBeVisible()
  await page.getByRole('button', { name: 'Edit layout' }).click()
  await expect(page.getByText('Loading bay')).toBeVisible()
})

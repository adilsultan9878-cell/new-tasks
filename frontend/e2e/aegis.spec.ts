import { expect, test, type Page } from '@playwright/test'

async function signUpWithOrg(page: Page, org: string) {
  await page.goto('/register')
  await page.getByLabel('Full name').fill('Iot Engineer')
  await page.getByLabel('Work email').fill(`aegis-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`)
  await page.getByLabel('Password', { exact: true }).fill('Blue-Team-Lab-2026!')
  await page.getByRole('button', { name: 'Create account' }).click()
  await page.getByLabel('Organization name').fill(org)
  await page.getByRole('button', { name: 'Create organization' }).click()
  await expect(page).toHaveURL(/\/org\/[0-9a-f-]{36}$/)
  return page.url()
}

test('simulator → sensors, outputs and a camera zone, never counted as real', async ({ page }) => {
  const orgUrl = await signUpWithOrg(page, 'Aegis Lab')
  await page.goto(`${orgUrl}/iot`)
  await expect(page.getByText('No sensors yet')).toBeVisible()
  await page.getByRole('button', { name: 'Try the simulator' }).first().click()

  await expect(page.getByText('Server Room Gas')).toBeVisible()
  await expect(page.getByText('2 sensors out of range')).toBeVisible()
  await expect(page.getByText(/Buzzer on/)).toBeVisible()
  await expect(page.getByText('Simulated').first()).toBeVisible()

  await page.goto(`${orgUrl}/vision`)
  await expect(page.getByText('Simulated lobby camera', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Zones & privacy' }).click()
  const dialog = page.getByRole('dialog', { name: 'Simulated lobby camera' })
  const frame = dialog.getByRole('application', { name: 'Drag to draw a restricted zone' })
  const box = (await frame.boundingBox())!
  await page.mouse.move(box.x + box.width * 0.05, box.y + box.height * 0.1)
  await page.mouse.down()
  await page.mouse.move(box.x + box.width * 0.3, box.y + box.height * 0.6, { steps: 5 })
  await page.mouse.up()
  await dialog.getByLabel('Zone name').fill('Cash desk')
  await dialog.getByRole('button', { name: 'Add zone' }).click()
  await dialog.getByRole('button', { name: 'Save zones' }).click()
  await expect(dialog.getByRole('button', { name: 'Save zones' })).toBeDisabled()
  await page.keyboard.press('Escape')
  await expect(page.getByLabel('2 restricted zones')).toContainText('Cash desk')

  // Simulated records are excluded from the Command Center.
  await page.goto(orgUrl)
  await expect(page.getByTestId('kpi-Critical alerts')).toHaveText('0')
  await expect(page.getByText(/simulated records exist/)).toBeVisible()

  await page.goto(`${orgUrl}/iot`)
  await page.getByRole('button', { name: 'Clear simulation' }).click()
  await page.getByRole('button', { name: 'Yes, remove simulated data' }).click()
  await expect(page.getByText('No sensors yet')).toBeVisible()
})

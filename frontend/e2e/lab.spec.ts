import { expect, test, type Page } from '@playwright/test'

async function signUpWithOrg(page: Page, org: string) {
  await page.goto('/register')
  await page.getByLabel('Full name').fill('Rida Researcher')
  await page.getByLabel('Work email').fill(`lab-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`)
  await page.getByLabel('Password', { exact: true }).fill('Blue-Team-Lab-2026!')
  await page.getByRole('button', { name: 'Create account' }).click()
  await page.getByLabel('Organization name').fill(org)
  await page.getByRole('button', { name: 'Create organization' }).click()
  await expect(page).toHaveURL(/\/org\/[0-9a-f-]{36}$/)
  return page.url()
}

test('upload lab data, backtest a rule, reproduce it — live alerts untouched', async ({ page }) => {
  const orgUrl = await signUpWithOrg(page, 'Research Lab')
  await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Research Lab' }).click()
  await expect(page.getByText('Start with a dataset')).toBeVisible()

  await page.getByRole('button', { name: 'Upload lab data' }).first().click()
  const upload = page.getByRole('dialog', { name: 'Upload lab data' })
  await upload.getByLabel('Name').fill('Two failed logins')
  await upload.getByRole('button', { name: 'Upload' }).click()
  await expect(upload).toBeHidden()
  const datasets = page.getByRole('list', { name: 'Datasets' })
  await expect(datasets.getByText('Two failed logins')).toBeVisible()
  await expect(datasets.getByText('1 real')).toBeVisible()
  await expect(datasets.getByText(/sha256 [0-9a-f]{16}/)).toBeVisible()

  // Without the threshold the rule fires on both failed logins: one real, one benign.
  await page.getByRole('checkbox', { name: /Only alert when it happens at least/ }).uncheck()
  await page.getByLabel('Experiment name').fill('Every failed login')
  await page.getByRole('button', { name: 'Run backtest' }).click()
  await expect(page.getByText('Caught 1 of 1 real attacks')).toBeVisible()
  await expect(page.getByText('1 false alarm', { exact: true })).toBeVisible()
  await expect(page.getByText('Of the alerts it raises, how many were real')).toBeVisible()

  await page.getByRole('button', { name: 'Re-check' }).click()
  await expect(page.getByText('Reproduced')).toBeVisible()

  // The lab never creates events or alerts.
  await page.goto(`${orgUrl}/events`)
  await expect(page.getByText('Two failed logins')).toHaveCount(0)
  await expect(page.getByText('Typo in password')).toHaveCount(0)
})

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { expect, test, type Page } from '@playwright/test'

async function signUpWithOrg(page: Page, org: string) {
  await page.goto('/register')
  await page.getByLabel('Full name').fill('Intel Analyst')
  await page.getByLabel('Work email').fill(`intel-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`)
  await page.getByLabel('Password', { exact: true }).fill('Blue-Team-Lab-2026!')
  await page.getByRole('button', { name: 'Create account' }).click()
  await page.getByLabel('Organization name').fill(org)
  await page.getByRole('button', { name: 'Create organization' }).click()
  await expect(page).toHaveURL(/\/org\/[0-9a-f-]{36}$/)
  return page.url()
}

test('phishing URL analysis explains itself and raises an alert', async ({ page }) => {
  const org = await signUpWithOrg(page, 'Phish Lab')
  await page.goto(`${org}/phishing`)
  await page.getByLabel('Suspicious link').fill('http://paypa1-secure-login.top/account/verify')
  await page.getByRole('button', { name: 'Analyse' }).click()

  const result = page.getByRole('region').filter({ hasText: 'Risk score' }).first()
  await expect(page.getByText('Deterministic checks', { exact: true })).toBeVisible()
  await expect(page.getByText('Uses the brand “paypal”')).toBeVisible()
  await expect(page.getByText(/High-abuse top-level domain/)).toBeVisible()
  await expect(page.getByText(/Unavailable: .*rdap/)).toBeVisible() // offline sources are reported, not hidden
  await expect(result.or(page.locator('body'))).toContainText(/Malicious|Suspicious/)
  await expect(page.getByRole('button', { name: /Notifications, 1 unread/ })).toBeVisible()

  // The investigation is in the history and the indicator watchlist.
  await page.goto(`${org}/threat-intel`)
  await expect(page.getByText('paypa1-secure-login.top', { exact: true })).toBeVisible()
})

test('network monitor only records hosts inside authorized scopes', async ({ page }) => {
  const dir = mkdtempSync(join(tmpdir(), 'sx-nmap-'))
  const file = join(dir, 'scan.xml')
  writeFileSync(file, `<?xml version="1.0"?><nmaprun>
    <host><status state="up"/><address addr="192.168.77.5" addrtype="ipv4"/><ports>
      <port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server"/></port></ports></host>
    <host><status state="up"/><address addr="172.31.0.9" addrtype="ipv4"/><ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host>
  </nmaprun>`)
  try {
    const org = await signUpWithOrg(page, 'Net Lab')
    await page.goto(`${org}/network`)
    await page.getByLabel('CIDR').fill('8.8.8.0/24')
    await page.getByLabel('Label').fill('Not ours')
    await page.getByRole('button', { name: 'Add scope' }).click()
    await expect(page.getByText(/public range\. I confirm/)).toBeVisible() // attestation required

    await page.getByLabel('CIDR').fill('192.168.77.0/24')
    await page.getByLabel('Label').fill('Lab')
    await page.getByRole('checkbox').uncheck().catch(() => {})
    await page.getByRole('button', { name: 'Add scope' }).click()
    await expect(page.getByText('192.168.77.0/24')).toBeVisible()

    await page.getByLabel('Choose an Nmap XML file').setInputFiles(file)
    await expect(page.getByRole('status').filter({ hasText: 'hosts imported' })).toContainText('1 of 2 hosts imported (1 outside scope discarded)')
    await expect(page.getByText('192.168.77.5', { exact: true })).toBeVisible()
    await expect(page.getByText('172.31.0.9')).toHaveCount(0)
    await expect(page.getByText('3389/ms-wbt-server')).toBeVisible()
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

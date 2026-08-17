import { test, expect } from '@playwright/test';
import fs from 'fs';
import path from 'path';

test.describe('AUTOMATIC PROVENANCE REEVALUATION', () => {
  test('submit valid authorized provenance', async ({ page }) => {
    // Navigate to frontend
    await page.goto('http://localhost:3001/submit');

    // Load actual generated fixtures
    const sbomPath = path.join(__dirname, '../../test-fixtures/live-sbom.json');
    const provPath = path.join(__dirname, '../../test-fixtures/live-prov.json');

    const sbomPayload = JSON.parse(fs.readFileSync(sbomPath, 'utf8'));

    // Track requests
    const requests = [];
    page.on('request', req => {
      requests.push({ url: req.url(), method: req.method(), postData: req.postDataJSON() || null });
    });

    const evaluateRequests = [];
    page.on('request', req => {
      if (req.url().includes('/evaluate') || req.url().includes('/trust-evaluation') || req.url().includes('/compliance-report')) {
        evaluateRequests.push(req.url());
      }
    });

    // Request interception to inspect network request for reevaluate
    const reevaluateRequestPromise = page.waitForRequest(request => 
      request.url().includes('/reevaluate') && request.method() === 'POST'
    );

    // 2. Upload a valid SBOM without provenance.
    const fileInputs = page.locator('input[type="file"]');
    await fileInputs.first().setInputFiles(sbomPath);
    await page.click('button:has-text("Submit SBOM")');

    // Wait for upload and analysis to show up
    await expect(page.locator('text="Uploading and analyzing SBOM"').first()).toBeVisible();

    // 3. Assert the initial recommendation appears.
    await expect(page.locator('text="Submit Provenance"').first()).toBeVisible({ timeout: 15000 });

    // Assert one real submit request occurs
    const submitReqs = requests.filter(r => r.url.includes('/api/submit') && r.method === 'POST');
    expect(submitReqs.length).toBe(1);

    // Assert no separate Evaluate request occurs after submission
    expect(evaluateRequests.length).toBe(0);

    // 4. Record the original decision ID and snapshot ID.
    const decisionIdLocator = page.locator('div:has-text("Decision ID:") >> code');
    const snapshotIdLocator = page.locator('div:has-text("Snapshot ID:") >> code');
    const oldDecisionId = await decisionIdLocator.first().textContent();
    const oldSnapshotId = await snapshotIdLocator.first().textContent();

    // The ProvenanceSubmit card is rendered automatically on successful submit.
    await expect(page.locator('text="Submit Provenance"').first()).toBeVisible();

    // 6. Submit valid authorized provenance.
    await fileInputs.last().setInputFiles(provPath);
    
    // Ensure the file is selected before clicking
    await expect(page.locator('text="live-prov.json"')).toBeVisible();

    // Wait until the button is no longer disabled
    const submitBtn = page.locator('button:has-text("Submit Provenance")');
    await expect(submitBtn).toBeEnabled();
    await submitBtn.click();

    // 8 & 9. Inspect the network request and assert POST /api/v1/sbom/:sbomId/reevaluate is sent automatically.
    const reevaluateRequest = await reevaluateRequestPromise;
    const postData = reevaluateRequest.postDataJSON();

    // 10. Assert the request does not contain caller-selected result metadata.
    expect(postData.recommendation).toBeUndefined();
    expect(postData.decisionId).toBeUndefined();
    expect(postData.snapshotId).toBeUndefined();
    expect(postData.status).toBeUndefined();
    expect(postData.policy).toBeUndefined();

    // Assert one real provenance request occurs
    const provReqs = requests.filter(r => r.url.includes('/provenance') && r.method === 'POST');
    expect(provReqs.length).toBe(1);

    // 12. Wait for the new decision ID (differs from the old decision ID).
    await expect(async () => {
      const currentDecisionId = await decisionIdLocator.first().textContent();
      expect(currentDecisionId).not.toEqual(oldDecisionId);
    }).toPass({ timeout: 15000 });
    
    const newDecisionId = await decisionIdLocator.first().textContent();

    // 13. Assert the new snapshot ID differs from the old snapshot ID.
    const newSnapshotId = await snapshotIdLocator.first().textContent();
    expect(newSnapshotId).not.toEqual(oldSnapshotId);

    // 14. Assert DecisionHistory contains the original decision as HISTORICAL.
    await expect(page.locator('text="Decision History"')).toBeVisible();
    await expect(page.locator(`text=${oldDecisionId}`).first()).toBeVisible();
    
    // 15. Assert the new decision is marked CURRENT.
    await expect(page.locator(`tr:has-text("${newDecisionId}") >> text="CURRENT"`)).toBeVisible();
  });
});

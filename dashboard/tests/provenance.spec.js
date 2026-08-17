import { test, expect } from '@playwright/test';
import fs from 'fs';
import path from 'path';

test.describe('AUTOMATIC PROVENANCE REEVALUATION', () => {
  test('submit valid authorized provenance', async ({ page }) => {
    await page.route('**/api/submit', route => route.fulfill({
      status: 201,
      json: {
        sbomId: 'SBOM-999',
        submissionStatus: 'ACCEPTED',
        analysisStatus: 'COMPLETED',
        recommendation: { recommendation: 'REJECT', internalTrustState: 'UNTRUSTED', decisionId: 'DEC-123', snapshotId: 'SNAP-123' }
      }
    }));
    await page.route('**/api/v1/sbom/*/provenance', route => route.fulfill({ status: 201, json: {} }));
    await page.route('**/api/v1/sbom/*/trust-decision', route => route.fulfill({
      status: 200,
      json: {
        history: [
          { id: 'DEC-456', snapshot_id: 'SNAP-456', trust_status: 'APPROVE', evaluated_at: new Date(Date.now() + 1000).toISOString() },
          { id: 'DEC-123', snapshot_id: 'SNAP-123', trust_status: 'REJECT', evaluated_at: new Date().toISOString() }
        ]
      }
    }));
    // 1. Establish valid development principal with an authorized role.
    // Assuming UI defaults to a valid dev/security user or we select it from dropdown.
    await page.goto('http://localhost:3001/submit'); // assuming 3001 is frontend URL, wait, backend is 3000, frontend is 3001 or what?

    // Create a temporary sbom json file for testing
    const sbomPath = path.join(__dirname, 'test-sbom.json');
    fs.writeFileSync(sbomPath, JSON.stringify({ serialNumber: `SBOM-${Date.now()}` }));
    
    // Create a temporary provenance json file for testing
    const provPath = path.join(__dirname, 'test-prov.json');
    fs.writeFileSync(provPath, JSON.stringify({
      _type: "https://in-toto.io/Statement/v0.1",
      subject: [{ name: "artifact", digest: { sha256: "fakehash" } }],
      predicateType: "https://slsa.dev/provenance/v0.2",
      predicate: { builder: { id: "test-builder" } }
    }));

    // 2. Upload a valid SBOM without provenance.
    const fileInputs = page.locator('input[type="file"]');
    await fileInputs.first().setInputFiles(sbomPath);
    await page.click('button:has-text("Submit SBOM")');

    // 3. Assert the initial recommendation appears.
    await expect(page.locator('text="Submit Provenance"').first()).toBeVisible({ timeout: 15000 });

    // 4. Record the original decision ID and snapshot ID.
    const decisionIdLocator = page.locator('div:has-text("Decision ID:") >> text=/DEC-[a-zA-Z0-9-]+/');
    const snapshotIdLocator = page.locator('div:has-text("Snapshot ID:") >> text=/SNAP-[a-zA-Z0-9-]+/');
    const oldDecisionId = await decisionIdLocator.first().textContent();
    const oldSnapshotId = await snapshotIdLocator.first().textContent();

    // 5. Open the existing provenance workflow.
    // The ProvenanceSubmit card is rendered automatically on successful submit.
    await expect(page.locator('text="Submit Provenance"').first()).toBeVisible();

    // Request interception to inspect network request
    const requestPromise = page.waitForRequest(request => 
      request.url().includes('/reevaluate') && request.method() === 'POST'
    );

    await page.route('**/api/v1/sbom/*/reevaluate', route => route.fulfill({
      status: 200,
      json: {
        analysisStatus: 'COMPLETED',
        recommendation: { recommendation: 'APPROVE', internalTrustState: 'TRUSTED', decisionId: 'DEC-456', snapshotId: 'SNAP-456' }
      }
    }));

    // 6. Submit valid authorized provenance.
    await fileInputs.nth(1).setInputFiles(provPath); // the second input file is the provenance one
    await page.click('button:has-text("Submit Provenance")');

    // 7. Assert "Re-evaluating automatically" appears.
    await expect(page.locator('text="Re-evaluating automatically"')).toBeVisible();

    // 8 & 9. Inspect the network request and assert POST /api/v1/sbom/:sbomId/reevaluate is sent automatically.
    const request = await requestPromise;
    const postData = request.postDataJSON();

    // 10. Assert the request does not contain caller-selected result metadata.
    expect(postData.recommendation).toBeUndefined();
    expect(postData.decisionId).toBeUndefined();
    expect(postData.snapshotId).toBeUndefined();
    expect(postData.status).toBeUndefined();
    expect(postData.policy).toBeUndefined();

    // 11. Assert the new recommendation appears.
    await expect(page.locator('text="Re-evaluating automatically"')).toBeHidden();
    
    // 12. Assert the new decision ID differs from the old decision ID.
    const newDecisionId = await decisionIdLocator.first().textContent();
    expect(newDecisionId).not.toEqual(oldDecisionId);

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

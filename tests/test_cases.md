# Test Cases — CryptoDAA

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| TC1 | Sign with User A, verify with User A's public key | Upload file → Sign (User A, 2048-bit, SHA-256) → Verify (verifier = User A) | ✅ VALID |
| TC2 | Sign with User A, tamper file, verify | Upload file → Sign (User A) → Click "Tamper & Verify" | ❌ INVALID + tamper details + avalanche heatmap |
| TC3 | Sign with User A, verify with User B's public key | Upload file → Sign (User A) → Verify (verifier = User B) | ❌ INVALID |
| TC4 | Load corrupted .sig file, attempt verify | Manually edit a .sig JSON to corrupt the `signature` field → Upload + Verify | ❌ Error — corrupt/invalid signature |
| TC5 | Sign a large file (>1MB), benchmark performance | Upload 1MB+ file → Sign → Run Performance benchmark | ✅ VALID + performance metrics logged in audit |

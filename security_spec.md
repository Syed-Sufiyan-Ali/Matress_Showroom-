# Security Specification & "Dirty Dozen" Hardened TDD

## 1. Data Invariants
1. **Zero-Trust Identity**: Users cannot elevate their own role to 'owner' or modify other user accounts. The initial owner bootstrap is anchored to the system administrator email (`syedsufiyanali636@gmail.com`).
2. **Worker Financial Privacy**: Workers cannot access expenses, business settings, or audit logs. Workers can only read their own sales invoices (`resource.data.createdBy == request.auth.uid`) or sales created today, and cannot read sensitive profit reports.
3. **Audit Log Immutability**: Audit logs can only be created by signed-in users with their authentic identity (`createdBy == request.auth.uid`), and can NEVER be updated or deleted by anyone, especially workers.
4. **Inventory & Ledger Integrity**: Products cannot have negative stock or missing key attributes (brand, size, SKU, prices).
5. **Customer & Supplier Balances**: Workers can only record customer payments, not supplier factory payouts. Supplier payments and factory purchase orders are restricted to owner/admin.
6. **Path & Payload Constraints**: Document IDs and string fields must respect strict length and regex guards to prevent Denial-of-Wallet or injection attacks.

---

## 2. The "Dirty Dozen" Malicious Payloads

1. **Payload 1: Privilege Escalation via User Profile Self-Promotion**
   - Attempt by worker to set role to `owner`.
   ```json
   { "uid": "worker-1", "email": "worker@test.com", "role": "owner" }
   ```
   - Target: `PATCH /users/worker-1`
   - Expected: PERMISSION_DENIED

2. **Payload 2: Worker Unauthorized Access to Business Expenses**
   - Attempt by worker to read or write operational expense records.
   ```json
   { "title": "Rent Payment", "category": "rent", "amount": 80000, "createdBy": "worker-1" }
   ```
   - Target: `POST /expenses/exp-malicious`
   - Expected: PERMISSION_DENIED

3. **Payload 3: Worker Modifying or Deleting Audit Logs**
   - Attempt by worker to purge activity logs after a discrepancy.
   - Target: `DELETE /auditLogs/audit-1`
   - Expected: PERMISSION_DENIED

4. **Payload 4: Worker Viewing All Shop Invoices / Competitor Pricing**
   - Attempt by worker to query another worker's or owner's historical sales.
   - Target: `GET /sales/sale-from-owner`
   - Expected: PERMISSION_DENIED

5. **Payload 5: Worker Recording Factory Supplier Payouts**
   - Workers are only authorized for customer cash/bank recovery payments, not outbound supplier factory payouts.
   ```json
   { "type": "supplier_payment", "partyId": "sup-1", "partyName": "Master Molty", "amount": 500000, "createdBy": "worker-1" }
   ```
   - Target: `POST /payments/pay-sup-1`
   - Expected: PERMISSION_DENIED

6. **Payload 6: Ghost Field Injection (Shadow Update)**
   - Attempt to add undeclared admin flags on product updates.
   ```json
   { "currentStock": 20, "isApproved": true, "superAdminBypass": "granted" }
   ```
   - Target: `PATCH /products/prod-1`
   - Expected: PERMISSION_DENIED

7. **Payload 7: Denial of Wallet via 2MB Document Payload**
   - Attempt to inject huge junk payloads into customer notes or product names.
   ```json
   { "shopName": "A".repeat(50000) }
   ```
   - Target: `POST /customers/cust-bloat`
   - Expected: PERMISSION_DENIED

8. **Payload 8: Document ID Poisoning with Path Traversal / Special Characters**
   - Attempt to write to malformed document ID `/products/../../etc/passwd`.
   - Expected: PERMISSION_DENIED

9. **Payload 9: Unauthenticated Reader Scraping Customer Phone Numbers & Ledger**
   - Anonymous or signed-out scraper hitting `/customers`.
   - Expected: PERMISSION_DENIED

10. **Payload 10: Worker Overwriting Wholesale Settings / Tax Numbers**
    - Attempt by worker to change store name, bank details, or footer notes.
    ```json
    { "businessName": "Hacked Mattress Store" }
    ```
    - Target: `PUT /settings/general`
    - Expected: PERMISSION_DENIED

11. **Payload 11: Forged Creator ID (Identity Spoofing on Sale)**
    - Worker-2 submitting a sale claiming it was created by Owner.
    ```json
    { "invoiceNumber": "INV-999", "customerId": "c1", "totalAmount": 10000, "paidAmount": 10000, "remainingAmount": 0, "createdBy": "owner-uid-123" }
    ```
    - Target: `POST /sales/sale-spoofed`
    - Expected: PERMISSION_DENIED

12. **Payload 12: Negative or Zero Price Product Injection**
    - Submitting products with negative selling price or negative stock.
    ```json
    { "name": "Fake Foam", "sku": "FK-1", "brand": "Diamond", "size": "King", "purchasePrice": -100, "sellingPrice": -200, "currentStock": -50 }
    ```
    - Target: `POST /products/prod-bad`
    - Expected: PERMISSION_DENIED

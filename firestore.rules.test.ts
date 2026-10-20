/**
 * Security Rule Tests for Asaan Mattress POS & Inventory
 * Validates role-based isolation (Owner vs Worker) and prevents the "Dirty Dozen" vulnerabilities.
 */

export interface TestPayload {
  description: string;
  path: string;
  method: 'get' | 'create' | 'update' | 'delete';
  user: { uid: string; email?: string; role: 'owner' | 'worker' | 'anonymous' };
  data?: Record<string, unknown>;
  expectedOutcome: 'PERMISSION_DENIED' | 'SUCCESS';
}

export const dirtyDozenTests: TestPayload[] = [
  {
    description: 'Worker cannot self-promote to owner role',
    path: 'users/worker-1',
    method: 'update',
    user: { uid: 'worker-1', role: 'worker' },
    data: { role: 'owner' },
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    description: 'Worker cannot read or create business expenses',
    path: 'expenses/exp-1',
    method: 'create',
    user: { uid: 'worker-1', role: 'worker' },
    data: { title: 'Rent Payment', category: 'rent', amount: 80000, createdBy: 'worker-1' },
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    description: 'Worker cannot delete or modify audit logs',
    path: 'auditLogs/log-1',
    method: 'delete',
    user: { uid: 'worker-1', role: 'worker' },
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    description: 'Worker cannot view another worker or owner historical sales',
    path: 'sales/owner-sale-1',
    method: 'get',
    user: { uid: 'worker-1', role: 'worker' },
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    description: 'Worker cannot create supplier factory payments',
    path: 'payments/pay-1',
    method: 'create',
    user: { uid: 'worker-1', role: 'worker' },
    data: { type: 'supplier_payment', partyId: 'sup-1', partyName: 'MoltyFoam', amount: 300000, createdBy: 'worker-1' },
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    description: 'Reject undeclared shadow fields on product updates',
    path: 'products/prod-1',
    method: 'update',
    user: { uid: 'owner-1', role: 'owner' },
    data: { isApproved: true, ghostField: 'hacked' },
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    description: 'Reject oversize string payloads (Denial of Wallet)',
    path: 'customers/cust-1',
    method: 'create',
    user: { uid: 'owner-1', role: 'owner' },
    data: { shopName: 'A'.repeat(5000) },
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    description: 'Reject document ID poisoning with path traversal characters',
    path: 'products/../../etc/passwd',
    method: 'create',
    user: { uid: 'owner-1', role: 'owner' },
    data: { name: 'Mattress' },
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    description: 'Unauthenticated visitor cannot access customer ledger',
    path: 'customers/cust-1',
    method: 'get',
    user: { uid: '', role: 'anonymous' },
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    description: 'Worker cannot overwrite company settings or tax NTN',
    path: 'settings/general',
    method: 'update',
    user: { uid: 'worker-1', role: 'worker' },
    data: { businessName: 'Attacker Mattress' },
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    description: 'Identity spoofing rejected on sale submission',
    path: 'sales/sale-1',
    method: 'create',
    user: { uid: 'worker-2', role: 'worker' },
    data: { invoiceNumber: 'INV-1', customerId: 'c1', totalAmount: 10000, paidAmount: 10000, remainingAmount: 0, createdBy: 'owner-uid' },
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    description: 'Reject product with negative stock or negative price',
    path: 'products/prod-2',
    method: 'create',
    user: { uid: 'owner-1', role: 'owner' },
    data: { name: 'Invalid', sku: 'INV-1', brand: 'Master', size: 'King', purchasePrice: -100, sellingPrice: -200, currentStock: -5 },
    expectedOutcome: 'PERMISSION_DENIED',
  },
];

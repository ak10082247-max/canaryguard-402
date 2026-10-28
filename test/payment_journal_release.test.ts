import assert from 'node:assert/strict';
import test from 'node:test';
import { PaymentJournal } from '../src/payment_journal.js';

test('failed empty acquisitions may release a claim; prepared uncertain or completed results cannot be released',()=>{
  const journal=new PaymentJournal(':memory:');
  try {
    journal.claim('unacquired','request');
    assert.equal(journal.releaseUnacquired('unacquired'),true);
    assert.equal(journal.claim('unacquired','request'),null);
    journal.prepare('unacquired',{actual:'acquired output pending settlement'});
    assert.equal(journal.releaseUnacquired('unacquired'),false);
    assert.equal(journal.get('unacquired')?.phase,'pending');
    journal.complete('unacquired',{receipt:'settled'});
    assert.equal(journal.releaseUnacquired('unacquired'),false);
    assert.equal(journal.get('unacquired')?.phase,'completed');
  } finally {journal.close();}
});

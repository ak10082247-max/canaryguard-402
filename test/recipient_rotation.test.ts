import assert from 'node:assert/strict';
import test from 'node:test';
import { configuration, RECIPIENT, SOLANA_RECIPIENT } from '../src/config.js';

test('new merchant defaults and retired public environment setting route only to the owner replacement',()=>{
  assert.equal(RECIPIENT,'0x80E0Ae84679b7f11bE171DaADd492FBECf628cd6');
  assert.equal(SOLANA_RECIPIENT,'9wuMysgXwNhtQeqJgGByAiMYc4EjzZ5wUSmnjrrt3ffh');
  assert.equal(configuration({}).payTo,RECIPIENT);
  assert.equal(configuration({X402_RECIPIENT_ADDRESS:'0x73279fa4BadA7CAC888c62CDa4f5c8104765f6f1'}).payTo,RECIPIENT);
  assert.equal(configuration({X402_RECIPIENT_ADDRESS:'0x73279FA4BADA7CAC888C62CDA4F5C8104765F6F1'}).payTo,RECIPIENT);
  assert.equal(configuration({X402_RECIPIENT_ADDRESS:'0x1111111111111111111111111111111111111111'}).payTo,'0x1111111111111111111111111111111111111111');
});

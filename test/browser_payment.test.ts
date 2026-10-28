import assert from 'node:assert/strict';
import test from 'node:test';
import { createBasePurchase } from '../public/x402-browser.mjs';

const origin = 'https://canaryguard-test.example';
const payer = '0x' + '11'.repeat(20);
const quote = { scheme:'exact', network:'eip155:8453', asset:'0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
  amount:'17000',payTo:'0x80E0Ae84679b7f11bE171DaADd492FBECf628cd6',maxTimeoutSeconds:300,extra:{name:'USD Coin',version:'2'} };
const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64');
function harness(options: { quote?:any; receipt?:any; loseFirst?:boolean; failSwitch?:boolean; chain?:string } = {}) {
  const memory = new Map<string,string>();
  const storage = { getItem:(key:string)=>memory.get(key) || null, setItem:(key:string,value:string)=>memory.set(key,value), removeItem:(key:string)=>memory.delete(key) };
  const walletCalls:any[] = [], requests:any[] = [], confirmations:any[] = [];
  let paidAttempts = 0;
  const wallet = { request:async (call:any) => {
    walletCalls.push(call);
    if(call.method === 'eth_requestAccounts') return [payer];
    if(call.method === 'wallet_switchEthereumChain') { if(options.failSwitch) throw Error('Wallet rejected chain switch'); return null; }
    if(call.method === 'eth_chainId') return options.chain || '0x2105';
    if(call.method === 'eth_signTypedData_v4') return '0x' + '22'.repeat(65); // Unfunded mocked wallet, never sent to a network.
    throw Error('Unexpected wallet method');
  } };
  const request = async (url:string,init:any) => {
    requests.push({url,init});
    if(!init.headers['PAYMENT-SIGNATURE']) return new Response('{}',{status:402,headers:{'PAYMENT-REQUIRED':encode({x402Version:2,resource:{url},accepts:[{network:'solana:ignored'},options.quote || quote]})}});
    paidAttempts++;
    if(options.loseFirst && paidAttempts === 1) throw Error('Lost response after submission');
    const receipt = options.receipt === undefined ? {success:true,amount:(options.quote || quote).amount,payer,network:quote.network,resource:{url},transaction:'0x'+'33'.repeat(32)} : options.receipt;
    return new Response(JSON.stringify({status:'clean',sanitized_content:'actual output'}),{status:200,headers:{...(receipt ? {'PAYMENT-RESPONSE':encode(receipt)} : {}),...(paidAttempts>1 ? {'Idempotency-Replayed':'true'} : {})}});
  };
  const clientOptions = {origin,wallet,request,storage,now:()=>1700000000000,random:{getRandomValues:(bytes:Uint8Array)=>bytes.fill(4)},confirmQuote:async (value:any)=>{confirmations.push(value);return true;}};
  return {client:createBasePurchase(clientOptions), clientOptions, walletCalls,requests,confirmations};
}

test('browser signs the selected live quote amount and exact resource, with at most sixty seconds validity', async () => {
  const h = harness();
  const result = await h.client.buy('/v1/sanitize',{content:'hello'});
  assert.equal(result.paid,true);
  const signed = JSON.parse(h.walletCalls.find(call=>call.method==='eth_signTypedData_v4').params[1]);
  assert.equal(signed.message.value,'17000');
  assert.equal(signed.message.validBefore,'1700000060');
  const payload = JSON.parse(Buffer.from(h.requests[1].init.headers['PAYMENT-SIGNATURE'],'base64').toString());
  assert.deepEqual(payload.accepted,quote);
  assert.equal(payload.resource.url,origin+'/v1/sanitize');
  assert.equal(h.requests[0].init.body,h.requests[1].init.body);
  assert.equal(h.confirmations[0].amountUsdc,'0.017000');
  assert.equal(h.client.hasPending(),false);
});

test('lost paid response survives client recreation, blocks replacement and recovers identical authorization/body', async () => {
  const h = harness({loseFirst:true});
  await assert.rejects(h.client.buy('/v1/sanitize',{content:'original'}),/Lost response/);
  assert.equal(h.client.hasPending(),true);
  const resumed = createBasePurchase(h.clientOptions);
  await assert.rejects(resumed.buy('/v1/sanitize',{content:'different'}),/needs recovery/);
  const result = await resumed.recover();
  assert.equal(result.replayed,true);
  assert.equal(result.request.content,'original');
  assert.equal(h.requests[1].init.body,h.requests[2].init.body);
  assert.equal(h.requests[1].init.headers['PAYMENT-SIGNATURE'],h.requests[2].init.headers['PAYMENT-SIGNATURE']);
  assert.equal(h.walletCalls.filter(call=>call.method==='eth_signTypedData_v4').length,1);
});

test('missing or mismatched receipt is never presented as settled and retains recovery proof', async () => {
  for(const receipt of [null,{success:true,transaction:'0x'+'33'.repeat(32)}, {success:true,amount:'1',payer,network:quote.network,resource:{url:origin+'/v1/sanitize'},transaction:'0x'+'33'.repeat(32)}]) {
    const h = harness({receipt});
    await assert.rejects(h.client.buy('/v1/sanitize',{content:'hello'}),/no matching settlement receipt/);
    assert.equal(h.client.hasPending(),true);
  }
});

test('untrusted quote terms are rejected before connecting or signing a wallet', async () => {
  for(const change of [{amount:'20001'},{payTo:payer},{asset:payer},{scheme:'upto'},{extra:{name:'Fake Coin',version:'2'}},{maxTimeoutSeconds:0}]) {
    const h = harness({quote:{...quote,...change}});
    await assert.rejects(h.client.buy('/v1/sanitize',{content:'hello'}),/quote/);
    assert.equal(h.walletCalls.length,0);
    assert.equal(h.client.hasPending(),false);
  }
});

test('wallet chain switch rejection or wrong active chain prevents signing and submission', async () => {
  for(const options of [{failSwitch:true},{chain:'0x1'}]) {
    const h = harness(options);
    await assert.rejects(h.client.buy('/v1/sanitize',{content:'hello'}));
    assert.equal(h.walletCalls.filter(call=>call.method==='eth_signTypedData_v4').length,0);
    assert.equal(h.requests.length,1);
  }
});

test('server-provided shorter quote expiry is honored', async () => {
  const h = harness({quote:{...quote,maxTimeoutSeconds:20}});
  await h.client.buy('/v1/sanitize',{content:'hello'});
  const signed = JSON.parse(h.walletCalls.find(call=>call.method==='eth_signTypedData_v4').params[1]);
  assert.equal(signed.message.validBefore,'1700000020');
});

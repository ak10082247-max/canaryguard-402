import assert from 'node:assert/strict';
import test from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { ENDPOINT_SPECS } from '../src/config.js';

test('local stdio MCP executes actual requested content and never returns a documented example as paid analysis',async t=>{
  const transport=new StdioClientTransport({command:process.execPath,args:['--import','tsx','src/stdio.ts'],
    // Retain only OS paths for the unfunded subprocess; no provider credentials.
    env:Object.fromEntries(['PATH','Path','SystemRoot','SYSTEMROOT','TEMP','TMP','USERPROFILE','LOCALAPPDATA'].filter(key=>process.env[key]).map(key=>[key,process.env[key]!])),stderr:'pipe'});
  const client=new Client({name:'offline-stdio-regression',version:'1'},{capabilities:{}});
  t.after(async()=>{await client.close();});
  await client.connect(transport);
  const list=await client.listTools();
  assert.equal(list.tools.some(tool=>['getPolymarketVerifiedOdds','getPolymarketOddsPulse','nansenTokenScreener'].includes(tool.name)),false);
  assert.match(list.tools.find(tool=>tool.name==='canary_sanitize')!.description!,/no x402 charge/);
  const text='OWNER_OFFLINE_STDIO_CONTENT_20261027';
  const result=await client.callTool({name:'canary_sanitize',arguments:{content:text,strict_mode:true}});
  assert.equal((result.structuredContent as any).sanitized_content,text);
  const token=ENDPOINT_SPECS.find(spec=>spec.path==='/v1/base/token')!;
  assert.ok(token);
  const invalid=await client.callTool({name:token.operationId,arguments:{token_address:'invalid'}});
  assert.equal(invalid.isError,true);
  assert.equal((invalid.structuredContent as any)?.charged,false);
  assert.notDeepEqual(invalid.structuredContent,token.outputExample);
});

import https from 'node:https';
import { lookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';

const denied = new BlockList();
for (const [ip, prefix] of [['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],['172.16.0.0',12],['192.0.0.0',24],['192.0.2.0',24],['192.168.0.0',16],['198.18.0.0',15],['198.51.100.0',24],['203.0.113.0',24],['224.0.0.0',3]] as [string,number][]) denied.addSubnet(ip,prefix,'ipv4');
export function publicAddress(ip: string) {
  if (isIP(ip) === 4) return !denied.check(ip,'ipv4');
  if (isIP(ip) !== 6 || !/^[23]/i.test(ip)) return false;
  return !/^(2001:(?:0*:|db8:)|2002:|3fff:)/i.test(ip);
}
export async function resolvePublic(value: string) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443') || isIP(url.hostname) || /(^localhost$|\.local$|\.internal$)/i.test(url.hostname)) throw new Error('Public HTTPS DNS hostname required');
  const addresses = await lookup(url.hostname,{ all:true });
  if (!addresses.length || addresses.some(a => !publicAddress(a.address))) throw new Error('All target addresses must be public');
  return { url, address: addresses.find(a=>a.family===4) || addresses[0] };
}
// DNS is checked once and the selected address is pinned to this TLS connection.
// Redirects are returned to the caller, never followed to an unchecked host.
export async function fetchPublicPage(value: string): Promise<{ status: number; ok: boolean; text: () => Promise<string> }> {
  const {url,address} = await resolvePublic(value);
  return new Promise((resolve,reject)=> {
    const req = https.get(url, { agent:false, signal:AbortSignal.timeout(10000), lookup: ((_host: any,opts: any,callback: any) => opts?.all ? callback(null,[address]) : callback(null,address.address,address.family)) as any,
      headers:{ 'User-Agent':'CanaryGuard-Evidence/1.0','Accept':'text/html, application/json, text/plain' } }, response=> {
      const chunks: Buffer[]=[];let length=0;
      response.on('data',(chunk: Buffer)=>{ length+=chunk.length;if(length>2*1024*1024) {response.destroy(new Error('Page exceeds size limit'));return;}chunks.push(chunk); });
      response.on('error',reject);response.on('end',()=> {const body=Buffer.concat(chunks).toString('utf8');resolve({status:response.statusCode||502,ok:!!response.statusCode&&response.statusCode>=200&&response.statusCode<300,text:async()=>body});});
    });
    req.setTimeout(10000,()=>req.destroy(new Error('Page timeout')));req.on('error',reject);
  });
}

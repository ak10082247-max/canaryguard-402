import { createPublicClient, fallback, http, type PublicClient, type Transport } from 'viem';
import { base } from 'viem/chains';
export const publicClient: PublicClient<Transport, typeof base> = createPublicClient({ chain: base, transport: fallback([...new Set([process.env.BASE_RPC_URL || 'https://mainnet.base.org','https://base-rpc.publicnode.com','https://base.drpc.org'])].map(url=>http(url,{timeout:10000,retryCount:0})),{rank:false,retryCount:0}) });

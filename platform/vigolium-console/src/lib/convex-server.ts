import 'server-only';
import { ConvexHttpClient } from 'convex/browser';

let client: ConvexHttpClient | null = null;

export function getConvexClient(): ConvexHttpClient {
  if (client) return client;

  const url = process.env.CONVEX_URL;
  if (!url) {
    throw new Error('CONVEX_URL environment variable is not set');
  }

  client = new ConvexHttpClient(url);
  return client;
}

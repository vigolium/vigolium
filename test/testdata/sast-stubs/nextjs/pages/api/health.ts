import type { NextApiRequest, NextApiResponse } from 'next';

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  const params = useRouter();
  const search = useSearchParams();
  res.status(200).json({ status: 'ok' });
}

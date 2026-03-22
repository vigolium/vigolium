import SettingsRoute from './SettingsRoute';

export function generateStaticParams() {
  return [
    { tab: [] },
    { tab: ['profile'] },
    { tab: ['team'] },
    { tab: ['theme'] },
    { tab: ['about'] },
  ];
}

export default function Page({ params }: { params: Promise<{ tab?: string[] }> }) {
  return <SettingsRoute params={params} />;
}

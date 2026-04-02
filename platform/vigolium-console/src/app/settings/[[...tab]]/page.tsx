import SettingsRoute from './SettingsRoute';

export function generateStaticParams() {
  return [
    { tab: [] },
    // Cloud tabs
    { tab: ['profile'] },
    { tab: ['team'] },
    { tab: ['theme'] },
    // Static/workbench tabs
    { tab: ['config'] },
    { tab: ['projects'] },
    { tab: ['about'] },
  ];
}

export default function Page({ params }: { params: Promise<{ tab?: string[] }> }) {
  return <SettingsRoute params={params} />;
}

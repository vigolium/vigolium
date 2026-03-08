import SourceReposRoute from './SourceReposRoute';

export function generateStaticParams() {
  return [{ id: [] }];
}

export default function Page() {
  return <SourceReposRoute />;
}

import HttpRecordsRoute from './HttpRecordsRoute';

export function generateStaticParams() {
  return [{ id: [] }];
}

export default function Page() {
  return <HttpRecordsRoute />;
}

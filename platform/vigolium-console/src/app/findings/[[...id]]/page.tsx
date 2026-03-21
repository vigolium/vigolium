import FindingsRoute from './FindingsRoute';

export function generateStaticParams() {
  return [{ id: [] }];
}

export default function Page() {
  return <FindingsRoute />;
}

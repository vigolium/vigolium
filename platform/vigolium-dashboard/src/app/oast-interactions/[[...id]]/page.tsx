import OASTInteractionsRoute from './OASTInteractionsRoute';

export function generateStaticParams() {
  return [{ id: [] }];
}

export default function Page() {
  return <OASTInteractionsRoute />;
}

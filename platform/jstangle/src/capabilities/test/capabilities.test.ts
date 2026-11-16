import { describe, expect, test } from 'vitest';
import { jstangle } from '../../index';

describe('protocol and browser capability packs', () => {
  test('links parsed GraphQL documents to HTTP endpoints and variables', async () => {
    const result = await jstangle(`
      const GetUser = gql\`query GetUser($id: ID!) { user(id: $id) { id name } }\`;
      fetch('/graphql', {method:'POST', body: JSON.stringify({query: GetUser, variables:{id:'123'}})});
    `, { profile: 'discovery', sourceUrl: 'https://example.test/app.js' });
    const linked = result.graphqlOperations.find((fact) => fact.endpoint?.rendered === '/graphql');
    expect(linked).toMatchObject({ operationType: 'query', operationName: 'GetUser', transport: 'http' });
    expect(linked?.variables).toEqual(expect.arrayContaining([expect.objectContaining({ name: 'id', type: 'ID!', required: true })]));
	expect(linked?.variables[0].value?.rendered).toContain('123');
    expect(linked?.document).toContain('query GetUser($id:ID!)');
  });

  test('extracts mutations, subscriptions, and persisted queries while rejecting malformed strings', async () => {
    const result = await jstangle(`
      const link = new HttpLink({uri:'/graphql'});
      const CreateUser = gql\`mutation CreateUser($name: String!) { createUser(name:$name) { id } }\`;
      useMutation(CreateUser);
      const Feed = gql\`subscription Feed { feed { id } }\`;
      useSubscription(Feed);
      fetch('/graphql', {method:'POST', body: JSON.stringify({extensions:{persistedQuery:{sha256Hash:'abc123'}}})});
      const falsePositive = 'this mutation word is not a GraphQL document';
    `, { profile: 'full' });
    expect(result.graphqlOperations.some((fact) => fact.operationType === 'mutation' && fact.operationName === 'CreateUser')).toBe(true);
    expect(result.graphqlOperations.some((fact) => fact.operationType === 'subscription' && fact.transport === 'websocket')).toBe(true);
    expect(result.graphqlOperations.some((fact) => fact.persistedQueryHash === 'abc123')).toBe(true);
    expect(result.graphqlOperations.some((fact) => fact.document?.includes('falsePositive'))).toBe(false);
  });

  test('preserves WebSocket/SSE metadata and messages', async () => {
    const result = await jstangle(`
      const ws = new WebSocket('wss://example.test/socket', ['graphql-transport-ws', 'chat']);
      ws.send(JSON.stringify({type:'subscribe', id:'1'}));
      ws.addEventListener('message', onMessage);
      const events = new EventSource('/events', {withCredentials:true});
      events.addEventListener('deployment', onDeployment);
	  const socket = io('https://example.test', {path:'/socket.io', extraHeaders:{'X-App':'web'}});
	  socket.emit('join', {room:'admin'});
	  fetch('/sse-stream', {headers:{Accept:'text/event-stream', 'Last-Event-ID':'cursor-7'}});
    `, { profile: 'discovery' });
    const native = result.webSockets.find((fact) => fact.library === 'native');
    expect(native?.subprotocols).toEqual(['graphql-transport-ws', 'chat']);
    expect(native?.outboundMessages[0]?.value.rendered).toContain('subscribe');
    expect(native?.inboundEventNames).toContain('message');
	const socketIO = result.webSockets.find((fact) => fact.library === 'socket.io');
	expect(socketIO?.options?.path.rendered).toBe('/socket.io');
	expect(socketIO?.headers?.[0].name.rendered).toBe('X-App');
	expect(socketIO?.outboundMessages[0].value.rendered).toContain('join');
    expect(result.eventSources[0]).toMatchObject({ withCredentials: true, eventNames: ['deployment'] });
	expect(result.eventSources.find((fact) => fact.library === 'fetch-stream')?.lastEventId?.rendered).toBe('cursor-7');
  });

  test('extracts framework route configs without treating arbitrary path props as routes', async () => {
    const result = await jstangle(`
      const routes = [
        {path:'/users/:id', component: UserPage, canActivate:[AuthGuard]},
        {path:'/admin', loadChildren:() => import('./admin.routes.js')},
        {path:'/old', redirectTo:'/new'},
      ];
      router.push('/settings');
      const visual = {path:'/not-a-route', color:'red'};
    `, { profile: 'discovery' });
    const paths = result.clientRoutes.map((route) => route.path.rendered);
    expect(paths).toEqual(expect.arrayContaining(['/users/:id', '/admin', '/old', '/settings']));
    expect(paths).not.toContain('/not-a-route');
    expect(result.clientRoutes.find((route) => route.path.rendered === '/admin')?.lazyAsset?.rendered).toBe('./admin.routes.js');
  });

  test('emits literal route meta, every gating key and React Router data routes', async () => {
    const result = await jstangle(`
      const adminMeta = { requiresAuth: !0, roles: ['admin', 'ops'] };
      const vueRoutes = [
        {path:'/settings', component: Settings, meta: { requiresAuth: true, permission: 'settings.write', level: 3,
          nested: { a: { b: { c: { d: 1 } } } }, check: currentUser.role, title: \`Settings\`, hidden: !1, cleared: void 0 }},
        {path:'/admin', component: Admin, meta: adminMeta, beforeEnter: requireAdmin},
        {path:'/inline', component: Inline, beforeEnter: (to, from, next) => { if (!store.user) next('/login'); else next(); }},
        {path:'/both', component: Both, beforeEnter: [requireLogin, requireAdmin]},
      ];
      const ngRoutes = [
        {path:'/reports', component: Reports, data: { roles: ['auditor'] }, canActivate: [() => inject(AuthService).isLoggedIn(), hasRole('auditor')], canMatch: [featureGuard]},
        {path:'/billing', loadChildren: () => import('./billing.js'), canLoad: [BillingGuard], canActivateChild: [ChildGuard.check], canDeactivate: [UnsavedGuard]},
      ];
      const dataRoutes = [
        {path:'/invoices', loader: invoicesLoader, Component: Invoices},
        {path:'/team', lazy: () => import('./team.js')},
        {path:'/inline-loader', loader: async ({ params }) => { const r = await fetch('/api/x'); return r.json(); }},
      ];
    `, { profile: 'discovery' });
    const route = (path: string) => result.clientRoutes.find((item) => item.path.rendered === path);

    expect(route('/settings')?.meta).toEqual({
      requiresAuth: true, permission: 'settings.write', level: 3,
      nested: { a: { b: { c: null } } }, check: null, title: 'Settings', hidden: false, cleared: null,
    });
    expect(route('/admin')?.meta).toEqual({ requiresAuth: true, roles: ['admin', 'ops'] });
    expect(route('/admin')?.guards).toEqual(['requireAdmin']);
    expect(route('/inline')?.guards).toEqual(['<inline>']);
    expect(route('/both')?.guards).toEqual(['requireLogin', 'requireAdmin']);

    expect(route('/reports')?.meta).toEqual({ roles: ['auditor'] });
    expect(route('/reports')?.guards).toEqual(['inject(AuthService).isLoggedIn()', 'hasRole("auditor")', 'featureGuard']);
    expect(route('/billing')?.guards).toEqual(['ChildGuard.check', 'BillingGuard']);
    expect(route('/billing')?.meta).toBeUndefined();

    expect(route('/invoices')).toMatchObject({ loader: 'invoicesLoader', routeType: 'page' });
    expect(route('/team')).toMatchObject({ routeType: 'lazy', lazyAsset: { rendered: './team.js' } });
    expect(route('/inline-loader')?.loader).toBe('<inline>');
  });

  test('bounds route meta and keeps non-route data objects out', async () => {
    const keys = Array.from({ length: 40 }, (_, index) => `k${index}: ${index}`).join(', ');
    const result = await jstangle(`
      const routes = [{path:'/big', component: Big, meta: { long: '${'x'.repeat(600)}', ${keys} }}];
      const chart = {path:'/not-a-route', data: { roles: ['x'] }};
    `, { profile: 'discovery' });
    const big = result.clientRoutes.find((item) => item.path.rendered === '/big');
    expect(Object.keys(big?.meta ?? {})).toHaveLength(32);
    expect(big?.meta?.long).toBeNull();
    expect(result.clientRoutes.map((item) => item.path.rendered)).not.toContain('/not-a-route');
  });

  test('extracts Next, SvelteKit, middleware, and Ionic route signals', async () => {
	const result = await jstangle(`
	  self.__BUILD_MANIFEST = {'/dashboard':['static/chunks/dashboard.js']};
	  const svelteRoutes = [{id:'/blog/[slug]', pattern:/blog/, page:()=>{}}];
	  const config = {matcher:['/admin/:path*', '/account']};
	  const link = <IonRouterLink routerLink="/mobile/settings" />;
	`, { profile: 'discovery', filename: 'routes.jsx' });
	const paths = result.clientRoutes.map((route) => route.path.rendered);
	expect(paths).toEqual(expect.arrayContaining(['/dashboard', '/blog/[slug]', '/admin/:path*', '/account', '/mobile/settings']));
	expect(result.clientRoutes.find((route) => route.path.rendered === '/dashboard')?.lazyAsset?.rendered).toBe('static/chunks/dashboard.js');
  });

  test('emits distinct browser security flow classes', async () => {
    const result = await jstangle(`
      location.href = location.hash;
      const script = document.createElement('script');
      script.src = location.search;
      fetch(document.cookie);
      window.parent.postMessage({token:'x'}, '*');
    `, { profile: 'full' });
    const classes = result.browserSecurityFlows.map((flow) => flow.flowType);
    expect(classes).toEqual(expect.arrayContaining([
      'openRedirect', 'scriptUrlInjection', 'sensitiveExfiltration', 'unsafePostMessage',
    ]));
  });

  test('flags message-data handlers only when origin/source validation is absent', async () => {
    const result = await jstangle(`
      window.addEventListener('message', (event) => { render(event.data); });
      window.addEventListener('message', (safe) => {
        if (safe.origin !== 'https://trusted.example') return;
        render(safe.data);
      });
      window.postMessage({hello:'world'}, '*');
    `, { profile: 'full' });
    const unsafe = result.browserSecurityFlows.filter((flow) => flow.flowType === 'unsafePostMessage');
    expect(unsafe).toHaveLength(1);
    expect(unsafe[0].sink).toContain('without origin/source validation');
  });

  test('links Apollo clients and preserves batched operations', async () => {
	const result = await jstangle(`
	  const link = new HttpLink({uri:'/graphql'});
	  const client = new ApolloClient({link});
	  const One = gql\`query One($id: ID!) { one(id:$id) { id } }\`;
	  const Two = gql\`mutation Two { two { id } }\`;
	  client.query({query: One, variables:{id:'7'}});
	  fetch('/graphql', {method:'POST', body:JSON.stringify([{query:One},{query:Two}])});
	`, { profile: 'discovery' });
	const linked = result.graphqlOperations.filter((fact) => fact.endpoint?.rendered === '/graphql');
	expect(linked.map((fact) => fact.operationName)).toEqual(expect.arrayContaining(['One', 'Two']));
	expect(linked.find((fact) => fact.operationName === 'One')?.variables[0].value?.rendered).toContain('7');
  });
});

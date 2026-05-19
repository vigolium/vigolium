/** Confirm M8 */
import * as fs from 'fs';
import { MenuBuilder } from '../../../src/services/MenuBuilder';
import { OpenAPIParser } from '../../../src/services/OpenAPIParser';
import { AcmeNormalizedOptions } from '../../../src/services/AcmeNormalizedOptions';
import { WebhookModel } from '../../../src/services/models/Webhook';
const S='00000000',O=new AcmeNormalizedOptions({}),N=5000;
const bomb=()=>({allOf:Array.from({length:N},(_,i)=>({type:'object',properties:{['p'+i]:{type:'string'}}}))});
const resp=(n:string)=>({'200':{description:'ok',content:{'application/json':{schema:{$ref:'#/components/schemas/'+n}}}}});
const walk=(xs:any[],o:any[]=[]):any[]=>{for(const x of xs||[]){if(x?.type==='operation')o.push(x);if(Array.isArray(x?.items))walk(x.items,o)}return o};
function runP(spec:any){const p=new OpenAPIParser(spec,undefined,O);let c=0;const m=p.mergeAllOf.bind(p);p.mergeAllOf=((...a:any[])=>{c++;return m(...a)}) as any;for(const op of walk(MenuBuilder.buildStructure(p,O)))for(const r of op.responses)void r.content;return c}
function runW(spec:any){const p=new OpenAPIParser(spec,undefined,O);let c=0;const m=p.mergeAllOf.bind(p);p.mergeAllOf=((...a:any[])=>{c++;return m(...a)}) as any;const wp={...(p.spec['x-webhooks']||{}),...(p.spec.webhooks||{})};const w=new WebhookModel(p,O,wp as any);for(const op of w.operations)for(const r of op.responses)void r.content;return {n:w.operations.length,c}}

test(`test_confirm_webhooks_parser_bug_parity_${S}`,()=>{
  const p=runP({openapi:'3.1.0',info:{title:'x',version:'1'},components:{schemas:{BP:bomb()}},paths:{'/t':{get:{operationId:'gp',responses:resp('BP')}}}});
  const w=runW({openapi:'3.1.0',info:{title:'x',version:'1'},components:{schemas:{BW:bomb()}},paths:{},webhooks:{orderEvent:{post:{operationId:'wh',responses:resp('BW')}}}});
  const x=runW({openapi:'3.1.0',info:{title:'x',version:'1'},components:{schemas:{BX:bomb()}},paths:{},'x-webhooks':{legacyOrderEvent:{post:{operationId:'xwh',responses:resp('BX')}}}});
  const both=runW({openapi:'3.1.0',info:{title:'x',version:'1'},components:{schemas:{BW:bomb(),BX:bomb()}},paths:{},webhooks:{orderEvent:{post:{operationId:'wh',responses:resp('BW')}}},'x-webhooks':{legacyOrderEvent:{post:{operationId:'xwh',responses:resp('BX')}}}});
  expect(p).toBeGreaterThan(N); expect(w.c).toBe(p); expect(x.c).toBe(p); expect(both.n).toBe(2); expect(both.c).toBe(p*2);
  expect(fs.readFileSync('src/services/SpecStore.ts','utf8')).toContain("...this.parser?.spec?.['x-webhooks']");
  expect(fs.readFileSync('src/services/MenuBuilder.ts','utf8')).toContain('getTags(parser, webhooks, true)');
  expect(fs.readFileSync('src/services/models/Webhook.ts','utf8')).toContain('parser.deref<OpenAPIPath>(infoOrRef || {})');
});

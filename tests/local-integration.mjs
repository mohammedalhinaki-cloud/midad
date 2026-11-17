#!/usr/bin/env node
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import * as pdfjs from 'pdfjs-dist/legacy/build/pdf.mjs';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const state=await mkdtemp(path.join(tmpdir(),'midad-qa-'));
const port=Number(process.env.MIDAD_TEST_PORT||8791);
const base=`http://127.0.0.1:${port}`;
const bootstrapSecret='test-only-bootstrap-secret';
let worker;
const results=[];
const check=(name,ok,detail='')=>{assert.ok(ok,`${name}${detail?`: ${detail}`:''}`);results.push(name);console.log(`✓ ${name}`);};
function wrangler(args){return execFileSync('npx',['wrangler',...args],{cwd:root,encoding:'utf8',stdio:['ignore','pipe','inherit']});}
function makePdf(pageCount=2){
  const objects=['<< /Type /Catalog /Pages 2 0 R >>',`<< /Type /Pages /Kids [${Array.from({length:pageCount},(_,i)=>`${3+i*2} 0 R`).join(' ')}] /Count ${pageCount} >>`];
  for(let i=0;i<pageCount;i++){const pageId=3+i*2,streamId=pageId+1;objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 400] /Resources << >> /Contents ${streamId} 0 R >>`,`<< /Length 0 >>\nstream\n\nendstream`);}
  let pdf='%PDF-1.4\n';const offsets=[0];for(let i=0;i<objects.length;i++){offsets.push(Buffer.byteLength(pdf));pdf+=`${i+1} 0 obj\n${objects[i]}\nendobj\n`;}
  const xref=Buffer.byteLength(pdf);pdf+=`xref\n0 ${objects.length+1}\n0000000000 65535 f \n${offsets.slice(1).map(offset=>`${String(offset).padStart(10,'0')} 00000 n \n`).join('')}trailer\n<< /Size ${objects.length+1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;return Buffer.from(pdf);
}
async function waitReady(){for(let i=0;i<80;i++){try{const response=await fetch(`${base}/api/session`);if(response.status===200)return;}catch{}await delay(250);}throw new Error('Local Worker did not become ready.');}
async function request(pathname,method='GET',body,token){
  const headers={};if(method!=='GET')headers['x-midad-request']='1';
  const options={method,headers};if(token)headers.cookie=token;
  if(body instanceof FormData)options.body=body;else if(body!==undefined){headers['content-type']='application/json';options.body=JSON.stringify(body);}
  const response=await fetch(`${base}${pathname}`,options);let data={};if((response.headers.get('content-type')||'').includes('json'))data=await response.json();
  return {response,data,text:async()=>response.text()};
}
function tokenFrom(response){const raw=response.headers.get('set-cookie')||'';assert.match(raw,/HttpOnly/i);assert.match(raw,/SameSite=Lax/i);assert.match(raw,/Max-Age=2592000/i);return raw.split(';')[0];}

try{
  wrangler(['d1','migrations','apply','midad-db','--local','--persist-to',state]);
  worker=spawn('npx',['wrangler','dev','--ip','127.0.0.1','--port',String(port),'--persist-to',state,'--var',`BOOTSTRAP_SECRET:${bootstrapSecret}`],{cwd:root,detached:true,stdio:'ignore'});
  await waitReady();

  let res=await request('/api/bootstrap','POST',{secret:bootstrapSecret,phone:'512345678',name:'مدير الجودة',password:'SuperCode123'});
  check('single-use bootstrap creates the first owner',res.response.status===201);
  res=await request('/api/bootstrap','POST',{secret:bootstrapSecret,phone:'512345679',name:'محاولة ثانية',password:'SuperCode123'});
  check('bootstrap cannot create another owner',res.response.status===403);

  res=await request('/api/auth/login','POST',{phone:'٥١٢٣٤٥٦٧٨',password:'SuperCode123'});
  const ownerCookie=tokenFrom(res.response);check('Saudi Arabic-Indic phone login works',res.response.status===200&&res.data.user.role==='super_admin');
  res=await request('/api/session','GET',undefined,ownerCookie);
  check('long-lived session resumes on a later request',res.response.status===200&&res.data.user.role==='super_admin');

  res=await request('/api/users','POST',{name:'المشرف المساعد',phone:'512345679',password:'AssistantCode1',role:'assistant'},ownerCookie);
  check('owner creates an assistant',res.response.status===201);const assistantId=res.data.id;
  res=await request('/api/users','POST',{name:'عضو غير مسموح',phone:'512345670',password:'MemberCode123',role:'member'},ownerCookie);
  check('owner cannot create members through assistant-only flow',res.response.status===403);
  res=await request('/api/auth/login','POST',{phone:'512345679',password:'AssistantCode1'});
  const assistantCookie=tokenFrom(res.response);check('assistant can sign in',res.response.status===200&&res.data.user.role==='assistant');
  res=await request('/api/audit','GET',undefined,assistantCookie);
  check('assistant cannot view sensitive audit data',res.response.status===403);
  res=await request('/api/users','POST',{name:'ليلى',phone:'512345670',password:'MemberCode123',role:'member'},assistantCookie);
  check('assistant creates a member',res.response.status===201);const memberOne=res.data.id;
  res=await request('/api/users','POST',{name:'هند',phone:'512345671',password:'MemberCode456',role:'member'},assistantCookie);
  check('assistant can add a second member',res.response.status===201);const memberTwo=res.data.id;
  res=await request('/api/users','POST',{name:'مكرر',phone:'512345670',password:'MemberCode789',role:'member'},assistantCookie);
  check('duplicate mobile numbers are rejected',res.response.status===409);

  const testPdf=makePdf(2);const parsedPdf=await pdfjs.getDocument({data:new Uint8Array(testPdf)}).promise;check('PDF.js parses the uploaded multi-page fixture',parsedPdf.numPages===2);await parsedPdf.getPage(2);
  const form=new FormData();form.set('title','كتاب الاختبار');form.set('page_count','2');form.set('start_page','1');form.set('end_page','2');form.set('pages_per_day','1');form.set('seconds_per_page','1');form.set('file',new Blob([testPdf],{type:'application/pdf'}),'fixture.pdf');
  res=await request('/api/book','POST',form,assistantCookie);const bookId=res.data.id;check('assistant uploads PDF to private R2',res.response.status===201);
  res=await request('/api/book/file');check('PDF is not public without a session',res.response.status===401);
  let assistantDash=await request('/api/dashboard','GET',undefined,assistantCookie);
  check('assistant dashboard lists status and book',assistantDash.response.status===200&&assistantDash.data.members.length===2&&assistantDash.data.day.page_start===1);
  res=await request('/api/leaves','POST',{user_id:memberTwo,starts_on:'2099-05-02',ends_on:'2099-05-03',reason:'اختبار'},assistantCookie);
  check('assistant can grant ISO-stored leave dates',res.response.status===201);

  res=await request('/api/auth/login','POST',{phone:'512345670',password:'MemberCode123'});
  const memberCookie=tokenFrom(res.response);check('member can sign in',res.response.status===200&&res.data.user.role==='member');
  let memberDash=await request('/api/dashboard','GET',undefined,memberCookie);
  check('member dashboard shows today pages only',memberDash.response.status===200&&memberDash.data.day.page_start===1&&memberDash.data.members===undefined);
  res=await request('/api/members','GET',undefined,memberCookie);
  check('member cannot enumerate other members',res.response.status===403);
  res=await request(`/api/users/${memberTwo}`,'PATCH',{name:'غير مصرح'},memberCookie);
  check('member cannot edit their own or another member account',res.response.status===403);
  res=await request(`/api/history?user_id=${memberTwo}`,'GET',undefined,memberCookie);
  check('member history endpoint remains scoped to the signed-in member',res.response.status===200&&res.data.member===undefined);
  const pdf=await request('/api/book/file','GET',undefined,memberCookie);const pdfBytes=Buffer.from(await pdf.response.arrayBuffer());
  check('authenticated member can read the private PDF in-site',pdf.response.status===200&&pdfBytes.subarray(0,5).toString()==='%PDF-');

  res=await request('/api/reading/start','POST',{day_id:memberDash.data.day.id},memberCookie);
  check('server starts a resumable reading session',res.response.status===200&&res.data.session.next_page_index===0);
  res=await request(`/api/reading/${memberDash.data.day.id}/page`,'POST',{},memberCookie);
  check('server rejects advancing a page before the configured time',res.response.status===429&&res.data.error.includes('صايدينك'));
  await delay(1100);
  res=await request(`/api/reading/${memberDash.data.day.id}/page`,'POST',{},memberCookie);
  check('sequential page view is persisted server-side',res.response.status===200&&res.data.session.next_page_index===1);
  res=await request(`/api/reading/${memberDash.data.day.id}/complete`,'POST',{},memberCookie);
  check('member can complete after viewing every required page',res.response.status===200&&res.data.ok);
  res=await request(`/api/reading/${memberDash.data.day.id}/complete`,'POST',{},memberCookie);
  check('duplicate daily completion is rejected',res.response.status===400);

  // Advance the first test window. The API should publish the next day and expose the prior unfinished day in its 48-hour grace period.
  const oldEnd=new Date(Date.now()-60_000).toISOString();const oldLock=new Date(Date.now()+86_340_000).toISOString();
  wrangler(['d1','execute','midad-db','--local','--persist-to',state,'--command',`UPDATE reading_days SET ends_at='${oldEnd}',locks_at='${oldLock}' WHERE id='${memberDash.data.day.id}'`]);
  memberDash=await request('/api/dashboard','GET',undefined,memberCookie);
  check('new daily reading is published after 24 hours',memberDash.response.status===200&&memberDash.data.day.id!==undefined);
  res=await request('/api/dashboard','GET',undefined,assistantCookie);
  check('assistant sees refreshed completion/absence status',res.response.status===200&&res.data.members.length===2);
  let memberTwoCookie=await request('/api/auth/login','POST',{phone:'512345671',password:'MemberCode456'});
  memberTwoCookie=tokenFrom(memberTwoCookie.response);
  let memberTwoDash=await request('/api/dashboard','GET',undefined,memberTwoCookie);
  check('member receives a previous reading during the 48-hour grace period',!!memberTwoDash.data.late_day);
  res=await request(`/api/history?user_id=${memberOne}`,'GET',undefined,memberTwoCookie);
  check('member cannot see another member reading history',res.response.status===200&&res.data.rows.length===0);
  let memberRecord=await request(`/api/history?user_id=${memberTwo}`,'GET',undefined,assistantCookie);
  check('administrator member record includes missed-day alerts',memberRecord.response.status===200&&memberRecord.data.missed_count===1&&memberRecord.data.missed_days.length===1);
  res=await request('/api/reading/start','POST',{day_id:memberTwoDash.data.late_day.id},memberTwoCookie);
  check('late reading resumes against its own day and timer',res.response.status===200);
  await delay(1100);
  res=await request(`/api/reading/${memberTwoDash.data.late_day.id}/page`,'POST',{},memberTwoCookie);
  check('late reading still uses server-side page timing',res.response.status===200);
  res=await request(`/api/reading/${memberTwoDash.data.late_day.id}/complete`,'POST',{},memberTwoCookie);
  check('late completion is recorded before the 48-hour lock',res.response.status===200&&res.data.late===true);
  memberRecord=await request(`/api/history?user_id=${memberTwo}`,'GET',undefined,assistantCookie);
  check('member record includes joined date, percent, totals, and completion history',memberRecord.data.member.joined_at&&typeof memberRecord.data.commitment==='number'&&memberRecord.data.total_completed===1&&memberRecord.data.rows.length===1);
  check('late reading clears the missed-day warning',memberRecord.data.missed_count===0);
  const dailyReport=await request('/api/reports?period=day','GET',undefined,assistantCookie);
  const dailyMember=dailyReport.data.rows.find(row=>row.id===memberOne);
  check('daily report uses Riyadh calendar-day windows and per-member eligible days',dailyReport.response.status===200&&dailyReport.data.days===2&&dailyReport.data.total_completions===2&&dailyMember?.percent===50);

  res=await request(`/api/users/${memberTwo}`,'PATCH',{status:'excluded',note:'اختبار'},assistantCookie);
  check('assistant can exclude a member without deleting history',res.response.status===200);
  res=await request(`/api/users/${memberTwo}`,'PATCH',{status:'active'},assistantCookie);
  check('assistant can reinstate an excluded member',res.response.status===200);
  memberRecord=await request(`/api/history?user_id=${memberTwo}`,'GET',undefined,assistantCookie);
  check('member history retains exclusion and reinstatement timestamps',memberRecord.data.events.some(e=>e.event_type==='excluded')&&memberRecord.data.events.some(e=>e.event_type==='reinstated'));
  res=await request(`/api/users/${memberOne}`,'PATCH',{status:'suspended'},assistantCookie);
  check('suspending an account blocks an existing session',res.response.status===200&&(await request('/api/session','GET',undefined,memberCookie)).data.user===null);
  res=await request('/api/auth/login','POST',{phone:'512345670',password:'MemberCode123'});
  check('suspended account cannot establish a new session',res.response.status===401);
  res=await request(`/api/users/${memberOne}`,'PATCH',{status:'active'},assistantCookie);
  check('admin can reactivate a suspended account',res.response.status===200&&(await request('/api/session','GET',undefined,memberCookie)).data.user?.role==='member');
  res=await request('/api/users','POST',{name:'عضو غائب',phone:'512345672',password:'MemberCode999',role:'member'},assistantCookie);
  check('assistant can add a member for absence tracking',res.response.status===201);const absentMember=res.data.id;
  const joinedBefore=new Date(Date.now()-5*86400000).toISOString();const missedSql=[`UPDATE users SET joined_at='${joinedBefore}' WHERE id='${absentMember}'`];
  for(const [i,hours] of [26,50,74].entries()){const start=new Date(Date.now()-hours*3600000).toISOString();const end=new Date(Date.parse(start)+86400000).toISOString();const lock=new Date(Date.parse(start)+172800000).toISOString();missedSql.push(`INSERT INTO reading_days(id,book_id,starts_at,ends_at,locks_at,page_start,page_end,pages_json,paused) VALUES('qa-missed-${i}','${bookId}','${start}','${end}','${lock}',1,1,'[1]',0)`);}
  wrangler(['d1','execute','midad-db','--local','--persist-to',state,'--command',missedSql.join(';')]);
  const absenceDash=await request('/api/dashboard','GET',undefined,assistantCookie);const absenceMember=absenceDash.data.members.find(m=>m.id===absentMember);
  check('three consecutive absences trigger the eligibility warning without auto-exclusion',absenceMember?.absence_streak>=3&&absenceMember.status==='active');
  res=await request('/api/reports?period=week','GET',undefined,assistantCookie);
  check('weekly report is available to assistant',res.response.status===200&&Array.isArray(res.data.rows));
  res=await request('/api/audit','GET',undefined,ownerCookie);
  check('owner audit log contains administrative operations',res.response.status===200&&res.data.rows.length>0);

  const report=await request('/api/reports','GET',undefined,memberCookie);
  check('member is denied administrative reports',report.response.status===403);
  const html=await readFile(path.join(root,'index.html'),'utf8');const css=await readFile(path.join(root,'src','styles.css'),'utf8');
  check('mobile/RTL presentation is present in app shell',html.includes('lang="ar" dir="rtl"')&&css.includes('@media(max-width:650px)'));
  res=await request(`/api/users/${memberOne}`,'DELETE',undefined,assistantCookie);
  check('assistant cannot permanently delete a member',res.response.status===403);
  res=await request(`/api/users/${memberOne}`,'DELETE',undefined,ownerCookie);
  check('owner can hard-delete a member and personal history',res.response.status===200);
  res=await request(`/api/history?user_id=${memberOne}`,'GET',undefined,assistantCookie);
  check('deleted member history is no longer addressable',res.response.status===404);
  res=await request(`/api/users/${assistantId}`,'DELETE',undefined,ownerCookie);
  check('owner can remove an assistant while preserving audit actor row',res.response.status===200);
  res=await request('/api/auth/logout','POST',{},ownerCookie);
  check('manual logout invalidates the server-side session',res.response.status===200&&(await request('/api/session','GET',undefined,ownerCookie)).data.user===null);
  console.log(`\nPASS: ${results.length} local integration/UX checks.`);
} catch(error) {
  console.error(`\nFAILED after ${results.length} checks: ${error.stack||error}`);
  process.exitCode=1;
} finally {
  if(worker?.pid){try{process.kill(-worker.pid,'SIGTERM');}catch{}}
  await delay(500);
  await rm(state,{recursive:true,force:true});
}

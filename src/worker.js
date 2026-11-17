const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers } });
const uid = () => crypto.randomUUID();
const iso = (ms = Date.now()) => new Date(ms).toISOString();
const cookieName = 'midad_session';
const bytesToHex = (bytes) => [...new Uint8Array(bytes)].map((v) => v.toString(16).padStart(2, '0')).join('');
const hexToBytes = (hex) => new Uint8Array(hex.match(/.{1,2}/g)?.map((b) => parseInt(b, 16)) || []);
const randomToken = (length = 32) => { const b = new Uint8Array(length); crypto.getRandomValues(b); return bytesToHex(b); };
async function sha256(value) { return bytesToHex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))); }
async function hashPassword(password) {
  const salt = randomToken(16);
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: hexToBytes(salt), iterations: 180000, hash: 'SHA-256' }, key, 256);
  return `pbkdf2$180000$${salt}$${bytesToHex(bits)}`;
}
async function verifyPassword(password, encoded) {
  try {
    const [, count, salt, expected] = encoded.split('$');
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: hexToBytes(salt), iterations: Number(count), hash: 'SHA-256' }, key, 256);
    return bytesToHex(bits) === expected;
  } catch { return false; }
}
function normalizePhone(raw) {
  let value = String(raw || '').replace(/[٠-٩۰-۹]/g, digit => String(digit.charCodeAt(0) >= 0x06f0 ? digit.charCodeAt(0)-0x06f0 : digit.charCodeAt(0)-0x0660)).replace(/[\s()+-]/g, '');
  if (value.startsWith('00966')) value = value.slice(5);
  else if (value.startsWith('966')) value = value.slice(3);
  if (value.startsWith('0')) value = value.slice(1);
  return /^5\d{8}$/.test(value) ? `966${value}` : null;
}
function safeUser(user) { return user && { id: user.id, name: user.name, phone: user.phone.slice(3), role: user.role, status: user.status, joined_at: user.joined_at }; }
async function body(request) { try { return await request.json(); } catch { return {}; } }
function err(message, status = 400) { return json({ error: message }, status); }
async function audit(env, actorId, action, entityType, entityId = null, details = {}) {
  await env.DB.prepare('INSERT INTO audit_logs(id,actor_id,action,entity_type,entity_id,details_json) VALUES(?,?,?,?,?,?)').bind(uid(), actorId, action, entityType, entityId, JSON.stringify(details)).run();
}
async function currentUser(request, env) {
  const token = request.headers.get('cookie')?.split(';').map(x => x.trim()).find(x => x.startsWith(`${cookieName}=`))?.slice(cookieName.length + 1);
  if (!token) return null;
  const row = await env.DB.prepare('SELECT u.*,s.id AS session_id,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').bind(await sha256(decodeURIComponent(token)), iso()).first();
  if (!row || row.status !== 'active' || row.deleted_at) return null;
  return row;
}
function requireRole(user, roles) { return !!user && roles.includes(user.role); }
function cookie(value, maxAge, request) {
  const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
  return `${cookieName}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}
function checkMutation(request) {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)) return true;
  return request.headers.get('x-midad-request') === '1';
}
function RiyadhDate(d = new Date()) {
  return new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Riyadh', year: 'numeric', month: '2-digit', day: '2-digit' }).format(d);
}
function isWithin(start, end, date = RiyadhDate()) { return start <= date && date <= end; }
async function getActiveDay(env, book) {
  const now = Date.now();
  let day = await env.DB.prepare('SELECT * FROM reading_days WHERE book_id=? ORDER BY starts_at DESC LIMIT 1').bind(book.id).first();
  if (!day || now >= Date.parse(day.ends_at)) {
    const start = now;
    const pageStart = day?.page_end ? Number(day.page_end) + 1 : Number(book.start_page || 1);
    if (pageStart <= Number(book.end_page || book.page_count)) {
      const endPage = Math.min(Number(book.end_page || book.page_count), pageStart + Number(book.pages_per_day || 3) - 1);
      const startIso = iso(start);
      const id = uid();
      await env.DB.prepare('INSERT INTO reading_days(id,book_id,starts_at,ends_at,locks_at,page_start,page_end,pages_json) VALUES(?,?,?,?,?,?,?,?)')
        .bind(id, book.id, startIso, iso(start + 86400000), iso(start + 172800000), pageStart, endPage, JSON.stringify(Array.from({length: endPage - pageStart + 1}, (_, i) => pageStart + i))).run();
      day = await env.DB.prepare('SELECT * FROM reading_days WHERE id=?').bind(id).first();
    } else { day = null; }
  }
  return day;
}
async function readingState(env, user, day, book) {
  if (!day || day.paused) return { day, reading: null, completed: false, paused: !!day?.paused, book };
  const today = RiyadhDate();
  const leave = user.role === 'member' ? await env.DB.prepare('SELECT id FROM member_leaves WHERE user_id=? AND starts_on<=? AND ends_on>=? LIMIT 1').bind(user.id, today, today).first() : null;
  const completion = await env.DB.prepare('SELECT completed_at,late FROM reading_completions WHERE reading_day_id=? AND user_id=?').bind(day.id, user.id).first();
  const session = await env.DB.prepare('SELECT * FROM reading_sessions WHERE reading_day_id=? AND user_id=?').bind(day.id, user.id).first();
  return { day, reading: session, completed: !!completion, completion, on_leave: !!leave, book };
}
async function memberSummaries(env, day) {
  const members=await env.DB.prepare("SELECT id,name,phone,status,joined_at,status_changed_at FROM users WHERE role='member' AND deleted_at IS NULL ORDER BY name COLLATE NOCASE").all();
  const schedule=await env.DB.prepare('SELECT id,starts_at,ends_at,paused FROM reading_days ORDER BY starts_at DESC LIMIT 90').all();
  const completions=await env.DB.prepare('SELECT user_id,reading_day_id,completed_at,late FROM reading_completions WHERE reading_day_id IN (SELECT id FROM reading_days ORDER BY starts_at DESC LIMIT 90)').all();
  const leaves=await env.DB.prepare('SELECT user_id,starts_on,ends_on FROM member_leaves').all();
  const completionMap=new Map((completions.results||[]).map(row=>[`${row.user_id}:${row.reading_day_id}`,row]));
  const memberLeaves=leaves.results||[];const today=RiyadhDate();
  const onLeave=(userId,date)=>memberLeaves.some(item=>item.user_id===userId&&item.starts_on<=date&&item.ends_on>=date);
  return (members.results||[]).map(member=>{
    const completion=day?completionMap.get(`${member.id}:${day.id}`):null;const leave=onLeave(member.id,today);let streak=0;
    for(const item of schedule.results||[]){
      if(Date.parse(item.ends_at)>Date.now()||item.paused)continue;
      if(completionMap.has(`${member.id}:${item.id}`))break;
      if(onLeave(member.id,RiyadhDate(new Date(item.starts_at))))continue;
      streak++;
    }
    return {...member,phone:member.phone.slice(3),completed_at:completion?.completed_at||null,late:!!completion?.late,on_leave:leave,absence_streak:completion||leave?0:streak};
  });
}
async function api(request, env) {
  const url = new URL(request.url); const path = url.pathname; const method = request.method;
  if (!checkMutation(request)) return err('تعذر التحقق من الطلب.', 403);

  if (path === '/api/bootstrap' && method === 'POST') {
    if (!env.BOOTSTRAP_SECRET) return err('التهيئة الأولى غير مفعلة.', 404);
    const data = await body(request);
    const count = await env.DB.prepare('SELECT COUNT(*) AS count FROM users').first();
    if (count.count > 0 || data.secret !== env.BOOTSTRAP_SECRET) return err('غير مصرح أو تم إنشاء الحساب الأول مسبقًا.', 403);
    const phone = normalizePhone(data.phone);
    if (!phone || !data.name?.trim() || String(data.password || '').length < 10) return err('أدخل الاسم ورقم جوال سعودي ورمز دخول من 10 خانات على الأقل.');
    const id = uid(); const hash = await hashPassword(data.password);
    await env.DB.prepare("INSERT INTO users(id,name,phone,role,password_hash) VALUES(?,?,?,'super_admin',?)").bind(id, data.name.trim(), phone, hash).run();
    await env.DB.prepare("INSERT INTO membership_events(id,user_id,event_type,actor_id) VALUES(?,?,'joined',?)").bind(uid(),id,id).run();
    return json({ ok: true, message: 'تم إنشاء حساب المشرف الرئيسي.' }, 201);
  }

  if (path === '/api/auth/login' && method === 'POST') {
    const data = await body(request); const phone = normalizePhone(data.phone);
    if (!phone || !data.password) return err('تحقق من رقم الجوال ورمز الدخول.', 400);
    const threshold=iso(Date.now()-15*60000);const attempts=await env.DB.prepare('SELECT COUNT(*) AS n FROM login_attempts WHERE phone=? AND attempted_at>?').bind(phone,threshold).first();
    if(Number(attempts.n||0)>=8)return err('محاولات كثيرة. انتظر قليلًا ثم أعد المحاولة.',429);
    const user = await env.DB.prepare('SELECT * FROM users WHERE phone=? AND deleted_at IS NULL').bind(phone).first();
    if (!user || user.status !== 'active' || !(await verifyPassword(data.password, user.password_hash))) {
      await env.DB.prepare('INSERT INTO login_attempts(id,phone) VALUES(?,?)').bind(uid(),phone).run();
      return err('رقم الجوال أو رمز الدخول غير صحيح، أو أن الحساب موقوف.', 401);
    }
    await env.DB.prepare('DELETE FROM login_attempts WHERE phone=?').bind(phone).run();
    const token = randomToken(); const days = Math.max(1, Math.min(90, Number(env.SESSION_DAYS || 30))); const expires = iso(Date.now() + days * 86400000);
    await env.DB.prepare('INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES(?,?,?,?)').bind(uid(),user.id,await sha256(token),expires).run();
    return json({ user: safeUser(user) }, 200, { 'set-cookie': cookie(token, days * 86400, request) });
  }
  if (path === '/api/auth/logout' && method === 'POST') {
    const user = await currentUser(request, env);
    const token = request.headers.get('cookie')?.split(';').map(x=>x.trim()).find(x=>x.startsWith(`${cookieName}=`))?.slice(cookieName.length+1);
    if (token) await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha256(decodeURIComponent(token))).run();
    return json({ ok: true },200,{'set-cookie':cookie('',0,request)});
  }
  const user = await currentUser(request, env);
  if (path === '/api/session' && method === 'GET') return user ? json({ user: safeUser(user) }) : json({ user: null }, 200, {'set-cookie':cookie('',0,request)});
  if (!user) return err('يلزم تسجيل الدخول.', 401);

  if (path === '/api/dashboard' && method === 'GET') {
    if (user.role === 'super_admin') {
      const admins = await env.DB.prepare("SELECT id,name,phone,status,joined_at FROM users WHERE role='assistant' AND deleted_at IS NULL ORDER BY name COLLATE NOCASE").all();
      return json({ admins: (admins.results || []).map(x => ({...x,phone:x.phone.slice(3)})) });
    }
    const book = await env.DB.prepare('SELECT * FROM books WHERE active=1 ORDER BY created_at DESC LIMIT 1').first();
    const day = book ? await getActiveDay(env, book) : null;
    if (user.role === 'assistant') {
      const history = book && day ? await env.DB.prepare('SELECT pages_json FROM reading_days WHERE book_id=? AND id<>?').bind(book.id,day.id).all() : {results:[]};
      const previous_pages = [...new Set((history.results||[]).flatMap(row=>{try{return JSON.parse(row.pages_json||'[]').map(Number)}catch{return []}}))];
      return json({ book, day, previous_pages, members: await memberSummaries(env, day), stats: { completed: day ? (await env.DB.prepare('SELECT COUNT(*) AS n FROM reading_completions WHERE reading_day_id=?').bind(day.id).first()).n : 0 } });
    }
    const state = await readingState(env,user,day,book);
    let late_day=null,late_book=null,late_reading=null;
    if(user.role==='member'&&day){
      const pending=await env.DB.prepare('SELECT rd.* FROM reading_days rd LEFT JOIN reading_completions rc ON rc.reading_day_id=rd.id AND rc.user_id=? WHERE rd.book_id=? AND rd.starts_at<? AND rd.locks_at>? AND rd.paused=0 AND rc.id IS NULL ORDER BY rd.starts_at DESC LIMIT 1').bind(user.id,day.book_id,day.starts_at,iso()).first();
      if(pending){late_day=pending;late_book=await env.DB.prepare('SELECT title FROM books WHERE id=?').bind(pending.book_id).first();late_reading=await env.DB.prepare('SELECT * FROM reading_sessions WHERE reading_day_id=? AND user_id=?').bind(pending.id,user.id).first();}
    }
    return json({ ...state, late_day, late_book, late_reading, user: safeUser(user) });
  }
  if (path === '/api/members' && method === 'GET') {
    if (!requireRole(user,['assistant','super_admin'])) return err('غير مصرح.',403);
    const members = await env.DB.prepare("SELECT id,name,phone,status,joined_at,status_changed_at FROM users WHERE role='member' AND deleted_at IS NULL ORDER BY name COLLATE NOCASE").all();
    return json({ members:(members.results||[]).map(m=>({...m,phone:m.phone.slice(3)})) });
  }
  if (path === '/api/users' && method === 'POST') {
    const data = await body(request); const phone = normalizePhone(data.phone);
    const createRole = user.role === 'super_admin' ? data.role === 'assistant' : user.role === 'assistant' && data.role === 'member';
    if (!createRole) return err('غير مصرح بإنشاء هذا الحساب.',403);
    if (!phone || !data.name?.trim() || String(data.password||'').length < 8) return err('أدخل الاسم ورقم جوال صحيحًا ورمز دخول مؤقتًا من 8 خانات على الأقل.');
    if (await env.DB.prepare('SELECT id FROM users WHERE phone=?').bind(phone).first()) return err('رقم الجوال مستخدم مسبقًا.',409);
    const id=uid();
    await env.DB.prepare('INSERT INTO users(id,name,phone,role,password_hash,created_by) VALUES(?,?,?,?,?,?)').bind(id,data.name.trim(),phone,data.role,await hashPassword(data.password),user.id).run();
    await env.DB.prepare("INSERT INTO membership_events(id,user_id,event_type,actor_id) VALUES(?,?, 'joined',?)").bind(uid(),id,user.id).run();
    await audit(env,user.id,'create',data.role==='member'?'member':'assistant',id,{name:data.name.trim()});
    return json({ id },201);
  }
  const userMatch = path.match(/^\/api\/users\/([^/]+)$/);
  if (userMatch && ['PATCH','DELETE'].includes(method)) {
    const target = await env.DB.prepare('SELECT * FROM users WHERE id=? AND deleted_at IS NULL').bind(userMatch[1]).first();
    if (!target) return err('الحساب غير موجود.',404);
    if (user.role === 'assistant' && target.role !== 'member') return err('غير مصرح.',403);
    if (user.role === 'super_admin' && target.role !== 'assistant' && target.role !== 'member') return err('غير مصرح.',403);
    const data=method==='PATCH'?await body(request):{};
    if (method==='DELETE') {
      if(user.role!=='super_admin'||!['member','assistant'].includes(target.role)) return err('الحذف متاح للمشرف الرئيسي فقط.',403);
      if(target.role==='assistant'){
        await env.DB.batch([env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(target.id),env.DB.prepare('UPDATE users SET deleted_at=?,status=\'suspended\',updated_at=? WHERE id=?').bind(iso(),iso(),target.id)]);
        await audit(env,user.id,'delete','assistant',target.id,{name:target.name});return json({ok:true});
      }
      await env.DB.batch([
        env.DB.prepare('DELETE FROM page_views WHERE session_id IN (SELECT id FROM reading_sessions WHERE user_id=?)').bind(target.id),
        env.DB.prepare('DELETE FROM reading_completions WHERE user_id=?').bind(target.id),
        env.DB.prepare('DELETE FROM reading_sessions WHERE user_id=?').bind(target.id),
        env.DB.prepare('DELETE FROM member_leaves WHERE user_id=?').bind(target.id),
        env.DB.prepare('DELETE FROM membership_events WHERE user_id=?').bind(target.id),
        env.DB.prepare('DELETE FROM audit_logs WHERE entity_id=? OR actor_id=?').bind(target.id,target.id),
        env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(target.id),
        env.DB.prepare('DELETE FROM users WHERE id=?').bind(target.id)
      ]);
      await audit(env,user.id,'permanent_delete','member',target.id,{name:target.name}); return json({ok:true});
    }
    if(data.name!==undefined && !String(data.name).trim()) return err('الاسم مطلوب.');
    if(data.phone!==undefined){const phone=normalizePhone(data.phone);if(!phone)return err('رقم الجوال غير صحيح.');if(await env.DB.prepare('SELECT id FROM users WHERE phone=? AND id<>?').bind(phone,target.id).first())return err('رقم الجوال مستخدم مسبقًا.',409);data.phone=phone;}
    if(data.status && !['active','suspended','excluded'].includes(data.status)) return err('حالة الحساب غير صحيحة.');
    const fields=[];const values=[];
    for(const key of ['name','phone','status']) if(data[key]!==undefined){fields.push(`${key}=?`);values.push(key==='name'?String(data[key]).trim():data[key]);}
    if(data.password){if(String(data.password).length<8)return err('رمز الدخول قصير جدًا.');fields.push('password_hash=?');values.push(await hashPassword(data.password));}
    if(!fields.length)return json({ok:true});
    fields.push('updated_at=?');values.push(iso());values.push(target.id);
    await env.DB.prepare(`UPDATE users SET ${fields.join(',')} WHERE id=?`).bind(...values).run();
    if(data.status && data.status!==target.status){const type=data.status==='excluded'?'excluded':data.status==='active'&&target.status==='excluded'?'reinstated':data.status==='active'?'reactivated':'suspended';await env.DB.prepare('UPDATE users SET status_changed_at=? WHERE id=?').bind(iso(),target.id).run();await env.DB.prepare('INSERT INTO membership_events(id,user_id,event_type,actor_id,note) VALUES(?,?,?,?,?)').bind(uid(),target.id,type,user.id,data.note||null).run();}
    await audit(env,user.id,'update',target.role,target.id,Object.fromEntries(Object.entries(data).filter(([k])=>k!=='password')));return json({ok:true});
  }
  if (path === '/api/book' && method === 'GET') {
    if (!requireRole(user,['assistant','super_admin'])) return err('غير مصرح.',403);
    const book=await env.DB.prepare('SELECT * FROM books ORDER BY created_at DESC LIMIT 1').first(); return json({book});
  }
  if (path === '/api/book' && method === 'POST') {
    if (!requireRole(user,['assistant','super_admin'])) return err('غير مصرح.',403);
    const form=await request.formData();const file=form.get('file');const title=String(form.get('title')||'').trim();
    if(!title)return err('اكتب اسم الكتاب.');
    const pageCount=Number(form.get('page_count')||0);const startPage=Number(form.get('start_page')||1);const pagesPerDay=Number(form.get('pages_per_day')||3);const seconds=Number(form.get('seconds_per_page')||60);const endPage=Number(form.get('end_page')||pageCount);
    if(!Number.isInteger(pageCount)||pageCount<1||startPage<1||endPage<startPage||endPage>pageCount||pagesPerDay<1||seconds<0||seconds>600)return err('راجع عدد الصفحات والإعدادات.');
    let fileKey;let uploaded=false;
    if(file&&typeof file==='object'&&file.size){
      if(file.size>100*1024*1024)return err('حجم الملف أكبر من 100 ميغابايت.');if(file.type!=='application/pdf')return err('الملف يجب أن يكون PDF.');
      const signature=new TextDecoder().decode(await file.slice(0,5).arrayBuffer());if(signature!=='%PDF-')return err('الملف المحدد ليس PDF صالحًا.');
      fileKey=`books/${uid()}.pdf`;try{await env.BOOKS.put(fileKey,file.stream(),{httpMetadata:{contentType:'application/pdf',cacheControl:'private, no-store'}});uploaded=true;}catch{return err('تعذر رفع الكتاب، حاول مرة أخرى.',502);}
    } else {const old=await env.DB.prepare('SELECT * FROM books WHERE active=1 ORDER BY created_at DESC LIMIT 1').first();if(!old)return err('اختر ملف PDF للكتاب.');fileKey=old.file_key;}
    const id=uid();
    try{await env.DB.batch([
      env.DB.prepare('UPDATE books SET active=0 WHERE active=1'),
      env.DB.prepare('INSERT INTO books(id,title,file_key,file_name,page_count,start_page,end_page,pages_per_day,seconds_per_page,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)').bind(id,title,fileKey,file?.name||'الكتاب الحالي.pdf',pageCount,startPage,endPage,pagesPerDay,seconds,user.id)
    ]);}catch(e){if(uploaded)await env.BOOKS.delete(fileKey);throw e;}
    await audit(env,user.id,'create_or_replace','book',id,{title,page_count:pageCount});return json({id},201);
  }
  if (path === '/api/book/file' && method === 'GET') {
    if (!requireRole(user,['member','assistant','super_admin'])) return err('غير مصرح.',403);
    const book=await env.DB.prepare('SELECT file_key,file_name FROM books WHERE active=1 ORDER BY created_at DESC LIMIT 1').first();if(!book)return err('لا يوجد كتاب حالي.',404);
    const object=await env.BOOKS.get(book.file_key);if(!object)return err('ملف الكتاب غير موجود.',404);
    const headers=new Headers({'content-type':'application/pdf','content-disposition':`inline; filename="${encodeURIComponent(book.file_name)}"`,'cache-control':'private, no-store','x-content-type-options':'nosniff'});object.writeHttpMetadata(headers);return new Response(object.body,{headers});
  }
  if (path === '/api/reading/pause' && method === 'POST') {
    if (!requireRole(user,['assistant','super_admin'])) return err('غير مصرح.',403);
    const data=await body(request);const book=await env.DB.prepare('SELECT * FROM books WHERE active=1 ORDER BY created_at DESC LIMIT 1').first();if(!book)return err('لا يوجد كتاب حالي.');
    const day=await getActiveDay(env,book);if(!day)return err('لا توجد قراءة متاحة.');
    await env.DB.prepare('UPDATE reading_days SET paused=?,pause_reason=? WHERE id=?').bind(data.paused?1:0,data.paused?String(data.reason||'').slice(0,500):null,day.id).run();await audit(env,user.id,data.paused?'pause_reading':'resume_reading','reading_day',day.id);return json({ok:true});
  }
  if (path === '/api/reading/settings' && method === 'PATCH') {
    if (!requireRole(user,['assistant','super_admin'])) return err('غير مصرح.',403);
    const data=await body(request);const day=await env.DB.prepare('SELECT * FROM reading_days ORDER BY starts_at DESC LIMIT 1').first();const book=await env.DB.prepare('SELECT * FROM books WHERE active=1 ORDER BY created_at DESC LIMIT 1').first();if(!book)return err('لا يوجد كتاب.');
    if(data.seconds_per_page!==undefined){const n=Number(data.seconds_per_page);if(!Number.isInteger(n)||n<0||n>600)return err('المدة يجب أن تكون بين صفر و600 ثانية.');await env.DB.prepare('UPDATE books SET seconds_per_page=?,updated_at=? WHERE id=?').bind(n,iso(),book.id).run();}
    if(day&&data.pages){const pages=[...new Set(data.pages.map(Number))].sort((a,b)=>a-b);if(!pages.length||pages.some(x=>!Number.isInteger(x)||x<1||x>book.page_count))return err('حدد صفحة واحدة على الأقل من داخل الكتاب.');await env.DB.prepare('UPDATE reading_days SET page_start=?,page_end=?,pages_json=? WHERE id=?').bind(pages[0],pages[pages.length-1],JSON.stringify(pages),day.id).run();await audit(env,user.id,'update_pages','reading_day',day.id,{pages});}
    await audit(env,user.id,'update_reading_settings','book',book.id,data.seconds_per_page!==undefined?{seconds_per_page:data.seconds_per_page}:{});return json({ok:true});
  }
  if (path === '/api/reading/start' && method === 'POST') {
    if(user.role!=='member')return err('هذه الصفحة للأعضاء فقط.',403);
    const data=await body(request);const day=await env.DB.prepare('SELECT * FROM reading_days WHERE id=?').bind(data.day_id).first();if(!day)return err('قراءة اليوم غير موجودة.',404);
    if(Date.now()>Date.parse(day.locks_at))return err('انتهت فترة القراءة.');if(day.paused)return err('القراءة متوقفة اليوم.');
    const readingDate=RiyadhDate(new Date(day.starts_at));const leave=await env.DB.prepare('SELECT id FROM member_leaves WHERE user_id=? AND starts_on<=? AND ends_on>=?').bind(user.id,readingDate,readingDate).first();if(leave)return err('أنت في إجازة لهذا اليوم.');
    if(await env.DB.prepare('SELECT id FROM reading_completions WHERE reading_day_id=? AND user_id=?').bind(day.id,user.id).first())return err('تم تسجيل قراءة هذا اليوم مسبقًا.');
    let session=await env.DB.prepare('SELECT * FROM reading_sessions WHERE reading_day_id=? AND user_id=?').bind(day.id,user.id).first();
    if(!session){session={id:uid(),reading_day_id:day.id,user_id:user.id,next_page_index:0,page_started_at:iso()};await env.DB.prepare('INSERT INTO reading_sessions(id,reading_day_id,user_id,next_page_index,page_started_at) VALUES(?,?,?,?,?)').bind(session.id,day.id,user.id,0,session.page_started_at).run();}
    return json({session,day,book:await env.DB.prepare('SELECT title,seconds_per_page,page_count FROM books WHERE id=?').bind(day.book_id).first()});
  }
  const readPath=path.match(/^\/api\/reading\/([^/]+)\/(page|complete)$/);
  if(readPath){
    if(user.role!=='member')return err('هذه الصفحة للأعضاء فقط.',403);
    const dayId=readPath[1];const day=await env.DB.prepare('SELECT * FROM reading_days WHERE id=?').bind(dayId).first();if(!day)return err('قراءة اليوم غير موجودة.',404);if(Date.now()>Date.parse(day.locks_at))return err('انتهت فترة تسجيل القراءة.');
    const session=await env.DB.prepare('SELECT * FROM reading_sessions WHERE reading_day_id=? AND user_id=?').bind(dayId,user.id).first();if(!session)return err('ابدأ القراءة أولًا.');if(session.completed_at)return err('تم إنهاء القراءة مسبقًا.');
    const pages=JSON.parse(day.pages_json||'[]');const book=await env.DB.prepare('SELECT seconds_per_page FROM books WHERE id=?').bind(day.book_id).first();const seconds=Number(book?.seconds_per_page??60);
    if(readPath[2]==='page'&&method==='POST'){
      if(session.next_page_index>=pages.length)return json({session,pages,can_complete:true});
      const now=Date.now();const elapsed=Math.floor((now-Date.parse(session.page_started_at))/1000);
      if(elapsed<seconds)return err('صايدينك! 🧐 ما شاء الله تقرأ بسرعة الضوء؟ ارجع كمّل الصفحة لا تتحمس',429);
      const pageNumber=pages[session.next_page_index];
      await env.DB.prepare('INSERT OR IGNORE INTO page_views(id,session_id,page_number,viewed_at,duration_seconds) VALUES(?,?,?,?,?)').bind(uid(),session.id,pageNumber,iso(now),elapsed).run();
      const nextIndex=session.next_page_index+1;await env.DB.prepare('UPDATE reading_sessions SET next_page_index=?,page_started_at=?,updated_at=? WHERE id=?').bind(nextIndex,iso(now),iso(now),session.id).run();
      const updated=await env.DB.prepare('SELECT * FROM reading_sessions WHERE id=?').bind(session.id).first();return json({session:updated,pages,can_complete:nextIndex>=pages.length});
    }
    if(readPath[2]==='complete'&&method==='POST'){
      if(session.next_page_index<pages.length)return err('أكمل الصفحات المطلوبة أولًا.');
      const viewed=await env.DB.prepare('SELECT COUNT(*) AS n FROM page_views WHERE session_id=?').bind(session.id).first();
      if(Number(viewed.n||0)<pages.length)return err('أكمل قراءة الصفحات المطلوبة أولًا.');
      const now=iso();const late=Date.now()>Date.parse(day.ends_at)?1:0;
      await env.DB.prepare('UPDATE reading_sessions SET completed_at=?,updated_at=? WHERE id=?').bind(now,now,session.id).run();
      await env.DB.prepare('INSERT OR IGNORE INTO reading_completions(id,reading_day_id,user_id,session_id,completed_at,late) VALUES(?,?,?,?,?,?)').bind(uid(),day.id,user.id,session.id,now,late).run();return json({ok:true,completed_at:now,late:!!late});
    }
  }
  if(path==='/api/history'&&method==='GET'){
    if(user.role==='member'){
      const rows=await env.DB.prepare('SELECT rc.completed_at,rc.late,rd.starts_at,rd.page_start,rd.page_end,b.title FROM reading_completions rc JOIN reading_days rd ON rd.id=rc.reading_day_id JOIN books b ON b.id=rd.book_id WHERE rc.user_id=? ORDER BY rc.completed_at DESC LIMIT 200').bind(user.id).all();return json({rows:rows.results||[]});
    }
    if(!requireRole(user,['assistant','super_admin']))return err('غير مصرح.',403);
    const id=url.searchParams.get('user_id');if(!id)return err('حدد العضو.');const target=await env.DB.prepare("SELECT id,name,phone,status,joined_at,status_changed_at FROM users WHERE id=? AND role='member'").bind(id).first();if(!target)return err('العضو غير موجود.',404);
    const rows=await env.DB.prepare('SELECT rc.completed_at,rc.late,rd.starts_at,rd.page_start,rd.page_end,b.title FROM reading_completions rc JOIN reading_days rd ON rd.id=rc.reading_day_id JOIN books b ON b.id=rd.book_id WHERE rc.user_id=? ORDER BY rc.completed_at DESC LIMIT 500').bind(id).all();
    const schedule=await env.DB.prepare('SELECT id,starts_at,page_start,page_end FROM reading_days WHERE starts_at>=? AND ends_at<? AND paused=0 ORDER BY starts_at DESC').bind(target.joined_at,iso()).all();const completedDays=await env.DB.prepare('SELECT reading_day_id FROM reading_completions WHERE user_id=?').bind(id).all();const memberLeaveRows=await env.DB.prepare('SELECT starts_on,ends_on FROM member_leaves WHERE user_id=?').bind(id).all();const completedSet=new Set((completedDays.results||[]).map(row=>row.reading_day_id));const leaveRows=memberLeaveRows.results||[];let eligible=0,missed=0;const missed_days=[];
    for(const rd of schedule.results||[]){const localDay=RiyadhDate(new Date(rd.starts_at));if(leaveRows.some(item=>item.starts_on<=localDay&&item.ends_on>=localDay))continue;eligible++;if(!completedSet.has(rd.id)){missed++;missed_days.push({starts_at:rd.starts_at,page_start:rd.page_start,page_end:rd.page_end});}}
    const totals=await env.DB.prepare('SELECT COUNT(*) AS completed FROM reading_completions WHERE user_id=?').bind(id).first();const events=await env.DB.prepare('SELECT event_type,note,occurred_at FROM membership_events WHERE user_id=? ORDER BY occurred_at DESC LIMIT 30').bind(id).all();
    return json({member:{...target,phone:target.phone.slice(3)},rows:rows.results||[],events:events.results||[],missed_count:missed,missed_days:missed_days.slice(0,20),commitment:eligible?Math.round(totals.completed*100/eligible):0,total_completed:totals.completed});
  }
  if(path==='/api/leaves'&&method==='POST'){
    if(!requireRole(user,['assistant','super_admin']))return err('غير مصرح.',403);const data=await body(request);const target=await env.DB.prepare("SELECT id FROM users WHERE id=? AND role='member' AND deleted_at IS NULL").bind(data.user_id).first();if(!target)return err('العضو غير موجود.');
    if(!/^\d{4}-\d{2}-\d{2}$/.test(data.starts_on||'')||!/^\d{4}-\d{2}-\d{2}$/.test(data.ends_on||'')||data.starts_on>data.ends_on)return err('حدد فترة إجازة صحيحة.');
    const id=uid();await env.DB.prepare('INSERT INTO member_leaves(id,user_id,starts_on,ends_on,reason,created_by) VALUES(?,?,?,?,?,?)').bind(id,data.user_id,data.starts_on,data.ends_on,String(data.reason||'').slice(0,300),user.id).run();await audit(env,user.id,'grant_leave','member',data.user_id,{starts_on:data.starts_on,ends_on:data.ends_on});return json({id},201);
  }
  if(path==='/api/reports'&&method==='GET'){
    if(!requireRole(user,['assistant','super_admin']))return err('غير مصرح.',403);const period=url.searchParams.get('period')==='week'?7:1;const since=iso(Date.now()-period*86400000);
    const rows=await env.DB.prepare("SELECT u.id,u.name,COUNT(rc.id) AS completed FROM users u LEFT JOIN reading_completions rc ON rc.user_id=u.id AND rc.completed_at>=? WHERE u.role='member' AND u.deleted_at IS NULL GROUP BY u.id ORDER BY u.name COLLATE NOCASE").bind(since).all();const activeDays=await env.DB.prepare('SELECT COUNT(*) AS n FROM reading_days WHERE starts_at>=? AND paused=0').bind(since).first();const days=activeDays.n||0;const summary=(rows.results||[]).map(row=>({...row,percent:days?Math.round(row.completed*100/days):0}));return json({period,rows:summary,days,total_completions:summary.reduce((sum,row)=>sum+row.completed,0)});
  }
  if(path==='/api/audit'&&method==='GET'){
    if(user.role!=='super_admin')return err('غير مصرح.',403);const rows=await env.DB.prepare('SELECT a.*,u.name AS actor_name FROM audit_logs a JOIN users u ON u.id=a.actor_id ORDER BY a.occurred_at DESC LIMIT 200').all();return json({rows:rows.results||[]});
  }
  return err('المسار غير موجود.',404);
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      try { return await api(request, env); }
      catch (e) { console.error('API failure',e); return json({error:'حدث خطأ غير متوقع. حاول مرة أخرى.'},500); }
    }
    if (env.ASSETS) {
      const response=await env.ASSETS.fetch(request);const headers=new Headers(response.headers);
      headers.set('x-content-type-options','nosniff');headers.set('referrer-policy','strict-origin-when-cross-origin');headers.set('x-frame-options','DENY');headers.set('permissions-policy','camera=(), microphone=(), geolocation=()');
      headers.set('content-security-policy',"default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; worker-src 'self' blob:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'");
      return new Response(response.body,{status:response.status,statusText:response.statusText,headers});
    }
    return new Response('مِدَاد — شغّل تطبيق الواجهة على المنفذ 5173.',{status:404});
  }
};

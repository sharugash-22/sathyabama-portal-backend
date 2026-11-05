import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import crypto from 'node:crypto';
import fs from 'node:fs';

const app=express(); const PORT=Number(process.env.PORT||3001);
const ERP=(process.env.ERP_BASE_URL||'https://erp.sathyabama.ac.in').replace(/\/$/,'');
const sessions=new Map();
app.disable('x-powered-by'); app.use(helmet({crossOriginResourcePolicy:{policy:'cross-origin'}}));
app.use(express.json({limit:'30kb'}));
app.use('/api/auth/login',rateLimit({windowMs:15*60*1000,limit:12,standardHeaders:true,legacyHeaders:false}));
const cookieName='sathy_portal_sid';
function cookie(req){const raw=req.headers.cookie||'';const item=raw.split(';').map(x=>x.trim()).find(x=>x.startsWith(cookieName+'='));return item?.slice(cookieName.length+1)}
function session(req,res,next){const id=cookie(req);const s=id&&sessions.get(id);if(!s||s.expires<Date.now()){if(id)sessions.delete(id);return res.status(401).json({error:'Please sign in again.'})}req.portalSession=s;req.portalSessionId=id;next()}
function setSession(res,data){const id=crypto.randomBytes(32).toString('hex');sessions.set(id,{...data,expires:Date.now()+8*60*60*1000});res.cookie(cookieName,id,{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:8*60*60*1000,path:'/'});}
function pick(obj,keys){const out={};for(const k of keys)if(obj?.[k]!==undefined&&obj[k]!==null)out[k]=obj[k];return out}
function findStudentId(login){return login?.StudentId??login?.studentId??login?.StudentID??login?.student_id??null}

function normKey(k){return String(k).replace(/[^a-z0-9]/gi,'').toLowerCase()}
function findNestedValue(root, aliases, depth=0){
  if(root==null||depth>6)return undefined;
  const wanted=new Set(aliases.map(normKey));
  if(Array.isArray(root)){
    for(const item of root){const found=findNestedValue(item,aliases,depth+1);if(found!==undefined&&found!==null&&found!=='')return found}
    return undefined;
  }
  if(typeof root!=='object')return undefined;
  for(const [key,value] of Object.entries(root)){
    if(wanted.has(normKey(key))&&value!==undefined&&value!==null&&value!=='')return value;
  }
  for(const value of Object.values(root)){
    if(value&&typeof value==='object'){
      const found=findNestedValue(value,aliases,depth+1);
      if(found!==undefined&&found!==null&&found!=='')return found;
    }
  }
  return undefined;
}
function mergeAcademicContext(s,...sources){
  const fields={
    degreeId:['DegreeId','DegreeID','degreeId'],
    courseId:['CourseId','CourseID','courseId'],
    programmeId:['ProgrammeId','ProgramId','ProgrammeID','ProgramID','programmeId'],
    batch:['Batch','BatchName','batch'],
    year:['CurrentYear','Year','AcademicYearNumber','year'],
    semester:['CurrentSemester','Semester','SemesterId','SemesterID','semester'],
    sectionId:['SectionId','SectionID','ProgrammeSectionId','programmeSectionId','sectionId']
  };
  for(const [target,aliases] of Object.entries(fields)){
    for(const source of sources){
      const value=findNestedValue(source,aliases);
      if(value!==undefined){s[target]=value;break}
    }
  }
}
function objectKeysOnly(value){
  if(Array.isArray(value))return {kind:'array',length:value.length,firstItemKeys:value[0]&&typeof value[0]==='object'?Object.keys(value[0]):[]};
  if(value&&typeof value==='object')return {kind:'object',keys:Object.keys(value)};
  return {kind:typeof value};
}
app.get('/api/health',(_req,res)=>res.json({status:'ok',service:'sathyabama-portal-api',mode:process.env.DEMO_MODE==='true'?'demo':'erp-configured'}));
app.post('/api/auth/login',async(req,res)=>{
  try{
  const registerNumber=String(req.body?.registerNumber||'').trim();const password=String(req.body?.password||'');
  if(!registerNumber||!password)return res.status(400).json({error:'Enter your register number and password.'});
  if(registerNumber.length>40||password.length>200)return res.status(400).json({error:'Invalid input.'});
  if(process.env.DEMO_MODE==='true'){
    if(registerNumber.toLowerCase()!=='demo'||password!=='demo123')return res.status(401).json({error:'Demo mode: use register number DEMO and password demo123.'});
    setSession(res,{mode:'demo',registerNumber:'DEMO',studentId:'DEMO-STUDENT',accessToken:null,student:{name:'Demo Student',registerNumber:'DEMO',programme:'B.E. Electronics and Communication Engineering',semester:3,section:'A',academicYear:'2026–27'}});
    return res.json({ok:true,mode:'demo',student:{name:'Demo Student',registerNumber:'DEMO'}});
  }
  try{
    const body={RegisterNumber:registerNumber,Password:password};
    // CAPTCHA fields are forwarded only when an ERP-approved integration has been configured.
    if(process.env.ERP_SEND_CAPTCHA_FIELDS==='true'){
      body.CaptchaKey=String(process.env.ERP_CAPTCHA_KEY||'');
      if(req.body.turnstileToken)body.TurnstileToken=String(req.body.turnstileToken);
    }
    const upstream=await fetch(ERP+(process.env.ERP_LOGIN_PATH||'/erp/api/v1.0/MasterStudent/login_y'),{method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(20000)});
    const data=await upstream.json().catch(()=>({}));
    if(!upstream.ok||data.status!==true){const message=String(data.message||data.error||'ERP did not accept this login.');return res.status(upstream.status===429?429:401).json({error:message,code:'ERP_LOGIN_REJECTED'});}
    const login=data.responseData?.login||data.responseData?.Login||{};const accessToken=data.responseData?.accessToken||data.accessToken;
    if(!accessToken)return res.status(502).json({error:'ERP login response did not include an access token.'});
    const studentId=findStudentId(login);
    setSession(res,{mode:'erp',registerNumber,studentId,accessToken,student:pick(login,['StudentName','Name','RegisterNumber','StudentId','ProgrammeName','Semester','DepartmentName'])});
    res.json({ok:true,mode:'erp',student:{name:login.StudentName||login.Name||'Student',registerNumber}});
  }catch(e){console.error('ERP login:',e.message);res.status(502).json({error:'Could not reach the ERP login service. Check connectivity and ERP integration settings.'})}
  }catch(outerErr){console.error('Login route crashed:',outerErr);res.status(500).json({error:'Server error: '+outerErr.message})}
});
function extractAcademicHistory(root){
  const rows=[];
  const seen=new Set();
  const visit=(value,depth=0)=>{
    if(value==null||depth>7)return;
    if(Array.isArray(value)){for(const item of value)visit(item,depth+1);return;}
    if(typeof value!=='object')return;
    for(const [key,child] of Object.entries(value)){
      if(normKey(key)==='studentacademic'||normKey(key)==='academicrecords'||normKey(key)==='studentacademicdetails'){
        const candidates=Array.isArray(child)?child:(child&&typeof child==='object'?[child]:[]);
        for(const row of candidates){
          if(!row||typeof row!=='object')continue;
          const semester=findNestedValue(row,['Semester','SemesterId','SemesterNo']);
          const academicYear=findNestedValue(row,['AcademicYear','AcademicYearName','YearName']);
          const monthId=findNestedValue(row,['AcademicMonthId','AcademicMonthID','MonthId']);
          if(semester==null||academicYear==null||monthId==null)continue;
          const item={semester:Number(semester),academicYear:String(academicYear),academicMonthId:Number(monthId)};
          if(!Number.isFinite(item.semester)||!Number.isFinite(item.academicMonthId))continue;
          const id=[item.semester,item.academicYear,item.academicMonthId].join('|');
          if(!seen.has(id)){seen.add(id);rows.push(item);}
        }
      }
      if(child&&typeof child==='object')visit(child,depth+1);
    }
  };
  visit(root);
  return rows;
}
function academicPeriodLabel(monthId){return Number(monthId)===1?'April–May':Number(monthId)===2?'October–November':`Academic month ${monthId}`;}

app.get('/api/student/me',session,async(req,res)=>{
  const s=req.portalSession;
  if(s.mode==='demo')return res.json({mode:'demo',student:s.student,profileStatus:'sample'});
  try{
    if(!s.studentId){
      return res.json({mode:'erp',student:{...s.student,registerNumber:s.registerNumber},profileStatus:'student-id-not-returned'});
    }
    const upstream=await fetch(ERP+(process.env.ERP_PROFILE_PATH||'/erp/api/v1.0/MasterStudent/view'),{
      method:'POST',
      headers:{'Content-Type':'application/json','Accept':'application/json','Authorization':`Bearer ${s.accessToken}`},
      body:JSON.stringify({StudentId:s.studentId}),
      signal:AbortSignal.timeout(20000)
    });
    const data=await upstream.json().catch(()=>null);
    if(!upstream.ok||data?.status!==true){
      console.error('[PROFILE] ERP profile request failed:',{httpStatus:upstream.status,apiStatus:data?.status,message:data?.message});
      return res.status(502).json({error:'ERP profile could not be loaded.'});
    }

    const root=data.responseData||{};
    const info=root.StudentInfo||root.studentInfo||root;
    const acad=root.studentAcademic||root.StudentAcademic||root.academic||{};
    const sources=[root,info,acad,s.student||{}];

    const name=findNestedValue(sources,['StudentName','Name','FullName','studentName'])||s.student?.name||'Student';
    const programme=findNestedValue(sources,['ProgrammeName','ProgramName','CourseName','DepartmentName']);
    const semester=findNestedValue(sources,['CurrentSemester','Semester','SemesterName']);
    const section=findNestedValue(sources,['Section','SectionName','SectionCode']);
    const student={
      ...pick(info,['StudentName','Name','RegisterNumber','Email','MobileNo','ProgrammeName','DepartmentName','Semester','Section']),
      name,
      registerNumber:s.registerNumber||findNestedValue(sources,['RegisterNumber','RegistrationNumber'])||'',
      ...(programme!==undefined?{programme}:{}),
      ...(semester!==undefined?{semester}:{}),
      ...(section!==undefined?{section}:{})
    };

    const noLeadingZero=(iso)=>{
      if(!iso)return null;
      const[y,m,d]=String(iso).slice(0,10).split('-');
      return m&&d?`${y}-${Number(m)}-${Number(d)}`:null;
    };
    const startDate=findNestedValue(sources,['AcademicMonthStartDate','AcademicStartDate']);
    const endDate=findNestedValue(sources,['AcademicMonthEndDate','AcademicEndDate']);
    s.academicStart=noLeadingZero(startDate)||s.academicStart;
    s.academicEnd=noLeadingZero(endDate)||s.academicEnd;
    s.academicStartISO=startDate?String(startDate).slice(0,10):s.academicStartISO;
    s.academicEndISO=endDate?String(endDate).slice(0,10):s.academicEndISO;

    // Identifiers may be nested in StudentInfo OR studentAcademic, depending on ERP response.
    mergeAcademicContext(s,...sources);
     s.academicHistory=extractAcademicHistory(root);

    console.log('[PROFILE] Academic context availability:',{
      degreeId: s.degreeId!=null,
      courseId: s.courseId!=null,
      programmeId: s.programmeId!=null,
      batch: s.batch!=null,
      year: s.year!=null,
      semester: s.semester!=null,
      sectionId: s.sectionId!=null
    });
    res.json({mode:'erp',student,profileStatus:'loaded'});
  }catch(e){
    console.error('[PROFILE] Retrieval error:',e.message);
    res.status(502).json({error:'Unable to retrieve the ERP profile right now.'});
  }
});

// ---------- Link flow: student signs in on the real ERP; the extension hands over that session ----------
const pending=new Map(); // code -> {sid, expires}
app.use('/api/link/complete',rateLimit({windowMs:15*60*1000,limit:30,standardHeaders:true,legacyHeaders:false}));
app.post('/api/link/start',(req,res)=>{
  const sid=crypto.randomBytes(32).toString('hex');
  sessions.set(sid,{mode:'pending',expires:Date.now()+8*60*60*1000});
  const code=crypto.randomBytes(5).toString('hex').slice(0,8).toUpperCase();
  pending.set(code,{sid,expires:Date.now()+5*60*1000});
  res.cookie(cookieName,sid,{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:8*60*60*1000,path:'/'});
  res.json({code,expiresInSeconds:300});
});
app.post('/api/link/complete',(req,res)=>{
  // Only the extension popup (chrome-extension:// origin) may complete a link.
  if(!String(req.headers.origin||'').startsWith('chrome-extension://'))return res.status(403).json({error:'Not allowed.'});
  res.set('Access-Control-Allow-Origin',req.headers.origin);
  const code=String(req.body?.code||'').toUpperCase();const p=pending.get(code);
  if(!p||p.expires<Date.now()){return res.status(400).json({error:'Pairing code is invalid or expired. Generate a new one on the portal.'})}
  const s=sessions.get(p.sid);if(!s)return res.status(400).json({error:'Portal session expired.'});
  const accessToken=String(req.body?.accessToken||'');if(!accessToken)return res.status(400).json({error:'No ERP session token.'});
  pending.delete(code);
  Object.assign(s,{mode:'erp',accessToken,studentId:req.body.studentId??null,registerNumber:String(req.body.registerNumber||''),student:{name:req.body.name||'Student',registerNumber:String(req.body.registerNumber||'')}});
  mergeAcademicContext(s,req.body,req.body.student||{});
  res.json({ok:true});
});
app.options('/api/link/complete',(req,res)=>{res.set({'Access-Control-Allow-Origin':req.headers.origin||'','Access-Control-Allow-Headers':'Content-Type','Access-Control-Allow-Methods':'POST'});res.sendStatus(204)});
app.get('/api/link/status',session,(req,res)=>res.json({linked:req.portalSession.mode==='erp',mode:req.portalSession.mode}));

// ---------- Config-driven ERP data routes (see backend/endpoints.json) ----------
const loadEndpoints=()=>{try{return JSON.parse(fs.readFileSync(new URL('./endpoints.json',import.meta.url),'utf8'))}catch{return{}}};
const noLeadingZeroToday=()=>{const d=new Date();return `${d.getFullYear()}-${d.getMonth()+1}-${d.getDate()}`};
const PLACEHOLDERS={
  studentId:(s)=>s.studentId??'', registerNumber:(s)=>s.registerNumber||'',
  fromDate:(s)=>s.academicStart||'', toDate:(s)=>s.academicEnd||'', today:()=>noLeadingZeroToday(),
  degreeId:(s)=>s.degreeId, courseId:(s)=>s.courseId, programmeId:(s)=>s.programmeId,
  batch:(s)=>s.batch||'', year:(s)=>s.year, semester:(s)=>s.semester, sectionId:(s)=>s.sectionId,
};
// A template value that is *exactly* one placeholder (e.g. "{degreeId}") is replaced with the
// session's actual value as-is, numbers staying numbers — the ERP's filter payload mixes typed
// numeric fieldValues with string ones, so stringifying everything could make a filter mismatch
// silently return zero rows. Placeholders mixed into a longer string still fall back to text.
const fill=(v,s)=>{
  if(typeof v==='string'){
    const exact=v.match(/^\{(\w+)\}$/);
    if(exact&&PLACEHOLDERS[exact[1]])return PLACEHOLDERS[exact[1]](s)??'';
    return v.replace(/\{(\w+)\}/g,(m,k)=>PLACEHOLDERS[k]?String(PLACEHOLDERS[k](s)??''):m);
  }
  if(Array.isArray(v))return v.map(x=>fill(x,s));
  if(v&&typeof v==='object')return Object.fromEntries(Object.entries(v).map(([k,x])=>[k,fill(x,s)]));
  return v;
};

// The ERP's daily attendance is whole-day only (present/absent per date — no subject or
// period breakdown). Until we also have the timetable's weekday->period->subject mapping,
// this is the most useful summary we can honestly compute from it.
function summarizeDailyAttendance(raw,s){
  // The ERP's ActualWorkingDays list runs past the requested ToDate (it includes the next
  // academic month's pre-loaded calendar too), so the real cutoff is the semester's own
  // AcademicMonth end date — not "today" — or future days leak into the total.
  const startISO=s?.academicStartISO,endISO=s?.academicEndISO;
  const workingDays=(raw?.ActualWorkingDays||[]).map(d=>d.Date).filter(d=>d&&(!startISO||d>=startISO)&&(!endISO||d<=endISO));
  const toISO=(ddmmyyyy)=>{const[dd,mm,yyyy]=String(ddmmyyyy).split('/');return dd&&mm&&yyyy?`${yyyy}-${mm.padStart(2,'0')}-${dd.padStart(2,'0')}`:null};
  // Confirmed against the ERP's own "Attendance Summary" tab: AttendanceType 0 = absent,
  // with every other working day in range implicitly present.
  const absentDates=(raw?.AttendanceDetails||[]).filter(a=>a.AttendanceType===0).map(a=>toISO(a.AttendanceDate)).filter(Boolean);
  const absentSet=new Set(absentDates);
  const totalDays=workingDays.length;
  const absentDays=workingDays.filter(d=>absentSet.has(d)).length;
  const presentDays=totalDays-absentDays;
  const percentage=totalDays?Math.round((presentDays/totalDays)*1000)/10:null;
  return{totalDays,presentDays,absentDays,percentage,absentDates:absentDates.sort()};
}

// (The hourly per-period endpoint's Status field turned out not to be trustworthy enough to
// build subject percentages from directly — see summarizeSubjectAttendanceFromTimetable below,
// which uses the confirmed-accurate day-level attendance instead.)

// A semester has exactly one fixed weekly timetable (confirmed), found via a two-step lookup:
// first the section's TimeTableId, then that table's full grid of periods. Cached on the
// session since it never changes mid-semester.
async function getTimetableRows(s){
  if(s.timetableRows)return s.timetableRows;

  // The profile endpoint must be called before timetable retrieval so these IDs are available.
  const required=['degreeId','courseId','programmeId','batch','semester','year','sectionId'];
  const missing=required.filter(k=>s[k]===undefined||s[k]===null||s[k]==='');
  if(missing.length){
    throw new Error(`Student academic identifiers missing from ERP profile: ${missing.join(', ')}`);
  }

  const headers={
    'Content-Type':'application/json',
    'Accept':'application/json',
    'Authorization':`Bearer ${s.accessToken}`
  };
  const idBody={
    DegreeId:s.degreeId,
    CourseId:s.courseId,
    ProgrammeId:s.programmeId,
    Batch:s.batch,
    Semester:s.semester,
    Year:s.year,
    SectionId:s.sectionId
  };

  const idRes=await fetch(ERP+'/erp/api/v1.0/TimeSetSection/getcourseTimeSet',{
    method:'POST',headers,body:JSON.stringify(idBody),signal:AbortSignal.timeout(20000)
  });
  const idData=await idRes.json().catch(()=>null);
  console.log('[TIMETABLE] Step 1:',{
    httpStatus:idRes.status,
    apiStatus:idData?.status,
    message:idData?.message,
    responseShape:objectKeysOnly(idData?.responseData)
  });
  if(!idRes.ok||idData?.status!==true){
    throw new Error(`Timetable ID lookup failed (HTTP ${idRes.status}).`);
  }

  const idSource=idData.responseData||{};
  const timeTableId=findNestedValue(idSource,['TimeTableId','TimeTableID','TimetableId','TimeSetId','TimeSetID']);
  const programmeSectionId=findNestedValue(idSource,['ProgrammeSectionId','ProgramSectionId','ProgrammeSectionID','SectionMappingId']);
  if(timeTableId==null||programmeSectionId==null){
    throw new Error('ERP timetable lookup returned success but did not include recognized timetable identifiers. Inspect [TIMETABLE] Step 1 response shape.');
  }

  const rowsRes=await fetch(ERP+'/erp/api/v1.0/TimetableDetails/getdatabyprogramme',{
    method:'POST',
    headers,
    body:JSON.stringify({TimeTableId:timeTableId,ProgrammeSectionId:programmeSectionId}),
    signal:AbortSignal.timeout(20000)
  });
  const rowsData=await rowsRes.json().catch(()=>null);
  console.log('[TIMETABLE] Step 2:',{
    httpStatus:rowsRes.status,
    apiStatus:rowsData?.status,
    message:rowsData?.message,
    responseShape:objectKeysOnly(rowsData?.responseData)
  });
  if(!rowsRes.ok||rowsData?.status!==true){
    throw new Error(`Timetable grid request failed (HTTP ${rowsRes.status}).`);
  }
  const rows=rowsData.responseData;
  if(!Array.isArray(rows)){
    throw new Error('ERP timetable grid response was not an array.');
  }
  s.timetableRows=rows;
  return rows;
}

// Day you were absent -> every subject scheduled that weekday counts as missed; day present ->
// every subject scheduled that weekday counts as attended. HourType 1 = an actual class period
// (2 and 3 are the short break and lunch, which carry no subject and are skipped).
function summarizeSubjectAttendanceFromTimetable(timetableRows,dailyRaw,s){
  const byWeekday=new Map();
  for(const r of timetableRows){
    if(r.HourType!==1||!r.SubjectCode)continue;
    if(!byWeekday.has(r.DayId))byWeekday.set(r.DayId,[]);
    byWeekday.get(r.DayId).push({code:r.SubjectCode,name:r.SubjectName});
  }
  const startISO=s.academicStartISO,endISO=s.academicEndISO;
  const workingDays=(dailyRaw?.ActualWorkingDays||[]).map(d=>d.Date).filter(d=>d&&(!startISO||d>=startISO)&&(!endISO||d<=endISO));
  const toISO=(ddmmyyyy)=>{const[dd,mm,yyyy]=String(ddmmyyyy).split('/');return dd&&mm&&yyyy?`${yyyy}-${mm.padStart(2,'0')}-${dd.padStart(2,'0')}`:null};
  const absentSet=new Set((dailyRaw?.AttendanceDetails||[]).filter(a=>a.AttendanceType===0).map(a=>toISO(a.AttendanceDate)).filter(Boolean));

  const bySubject=new Map();
  for(const date of workingDays){
    const[y,m,d]=date.split('-').map(Number);
    const weekday=new Date(y,m-1,d).getDay(); // 1=Mon .. 5=Fri, matching the timetable's DayId
    const subjects=byWeekday.get(weekday);
    if(!subjects)continue; // weekend or a day with nothing scheduled
    const present=!absentSet.has(date);
    for(const subj of subjects){
      if(!bySubject.has(subj.code))bySubject.set(subj.code,{code:subj.code,name:subj.name,present:0,total:0});
      const e=bySubject.get(subj.code);e.total++;if(present)e.present++;
    }
  }
  return[...bySubject.values()].map(e=>({...e,percentage:e.total?Math.round((e.present/e.total)*1000)/10:null})).sort((a,b)=>a.name.localeCompare(b.name));
}
const cache=new Map(); // per-session short cache so we never hammer the ERP
async function erpData(name,req,res){
  const s=req.portalSession;
  if(s.mode==='demo')return res.json({mode:'demo',status:'demo'});
  if(s.mode!=='erp')return res.status(401).json({error:'Link your ERP session first.'});
  const ep=loadEndpoints()[name];
  if(!ep||!ep.enabled)return res.json({mode:'erp',status:'not-configured',message:`"${name}" endpoint is not configured yet in backend/endpoints.json.`});
  const key=req.portalSessionId+':'+name,hit=cache.get(key);
  if(hit&&hit.t>Date.now()-60000)return res.json(hit.v);
  try{
    const up=await fetch(ERP+ep.path,{method:ep.method||'POST',headers:{'Content-Type':'application/json','Accept':'application/json','Authorization':`Bearer ${s.accessToken}`},body:(ep.method||'POST')==='GET'?undefined:JSON.stringify(fill(ep.body||{},s)),signal:AbortSignal.timeout(20000)});
    if(up.status===401||up.status===403){sessions.delete(req.portalSessionId);return res.status(401).json({error:'ERP session expired. Sign in on the ERP and link again.'})}
    const data=await up.json().catch(()=>null);
    if(!up.ok||data==null)return res.status(502).json({error:`ERP returned ${up.status}.`});
    const payload=data.responseData??data;
    // Subject-wise attendance is handled by its own dedicated route below (it needs a
    // two-step timetable lookup plus the daily data, not a single templated call).
    const v=name==='attendance'?{mode:'erp',status:'ok',kind:'daily-summary',summary:summarizeDailyAttendance(payload,s),raw:payload}
      :{mode:'erp',status:'ok',raw:payload};
    cache.set(key,{t:Date.now(),v});res.json(v);
  }catch{res.status(502).json({error:'Unable to reach the ERP right now.'})}
}
app.get('/api/student/attendance',session,(q,r)=>erpData('attendance',q,r));
app.get('/api/student/attendance-subjects',session,async(req,res)=>{
  const s=req.portalSession;
  if(s.mode==='demo')return res.json({mode:'demo',status:'demo'});
  if(s.mode!=='erp')return res.status(401).json({error:'Link your ERP session first.'});
  const key=req.portalSessionId+':subjectAttendance',hit=cache.get(key);
  if(hit&&hit.t>Date.now()-60000)return res.json(hit.v);
  try{
    const dailyEp=loadEndpoints().attendance;
    if(!dailyEp?.enabled||!dailyEp?.path)return res.status(503).json({error:'Attendance endpoint is not configured in backend/endpoints.json.'});
    const dailyRes=await fetch(ERP+dailyEp.path,{method:dailyEp.method||'POST',headers:{'Content-Type':'application/json','Accept':'application/json','Authorization':`Bearer ${s.accessToken}`},body:JSON.stringify(fill(dailyEp.body||{},s)),signal:AbortSignal.timeout(20000)});
    const dailyData=await dailyRes.json().catch(()=>null);
    if(!dailyRes.ok||dailyData?.status!==true)return res.status(502).json({error:'Could not load attendance for the subject breakdown.'});
    const timetableRows=await getTimetableRows(s);
    const subjects=summarizeSubjectAttendanceFromTimetable(timetableRows,dailyData.responseData,s);
    const v={mode:'erp',status:'ok',kind:'subject-summary',subjects};
    cache.set(key,{t:Date.now(),v});res.json(v);
  }catch(e){console.error('attendance-subjects:',e.message);res.status(502).json({error:'Unable to compute subject-wise attendance right now.'})}
});
app.get('/api/student/timetable',session,async(req,res)=>{
  const s=req.portalSession;
  if(s.mode==='demo')return res.json({mode:'demo',status:'demo'});
  if(s.mode!=='erp')return res.status(401).json({error:'Link your ERP session first.'});
  try{
    const rows=await getTimetableRows(s);
    res.json({mode:'erp',status:'ok',raw:rows});
  }catch(e){
    console.error('timetable:',e.message);
    res.status(502).json({mode:'erp',status:'unavailable',message:'The ERP timetable could not be loaded for this account.'});
  }
});
app.get('/api/student/hall-ticket',session,(q,r)=>erpData('hallTicket',q,r));
// ---------- CAE results (official studentCAEResult endpoint) ----------
app.get('/api/student/cae-results',session,async(req,res)=>{
  const s=req.portalSession;
  if(s.mode==='demo')return res.json({mode:'demo',status:'not-configured',cae:[]});
  if(s.mode!=='erp')return res.status(401).json({error:'Link your ERP session first.'});
  const registerNumber=String(s.registerNumber||'').trim();
  const semester=Number(s.semester||req.query.semester||0);
  const academicPeriods=Array.isArray(s.academicHistory)?s.academicHistory:[];
  const currentPeriod=academicPeriods.filter(p=>Number(p.semester)===semester).sort((a,b)=>a.academicYear.localeCompare(b.academicYear)||a.academicMonthId-b.academicMonthId).at(-1);
  if(!registerNumber||!semester||!currentPeriod)return res.status(422).json({status:'missing-context',error:'The ERP profile did not provide the current semester academic period. CAE results were not requested using guessed year or month values.'});
  const academicYear=currentPeriod.academicYear;
  const academicMonthId=currentPeriod.academicMonthId;
  try{
    const upstream=await fetch(ERP+'/erp/api/v1.0/CAEResult/studentCAEResult',{
      method:'POST',
      headers:{'Content-Type':'application/json','Accept':'application/json','Authorization':`Bearer ${s.accessToken}`},
      body:JSON.stringify({RegisterNumber:registerNumber,AcademicMonthId:academicMonthId,AcademicYear:academicYear,Semester:semester}),
      signal:AbortSignal.timeout(20000)
    });
    const payload=await upstream.json().catch(()=>null);
    if(!upstream.ok||payload?.status!==true){
      console.error('[CAE] ERP request failed:',{httpStatus:upstream.status,apiStatus:payload?.status,message:payload?.message});
      return res.status(502).json({status:'unavailable',error:'CAE results could not be loaded from the ERP.'});
    }
    const records=Array.isArray(payload.responseData)?payload.responseData:[];
    const cae=records.map(item=>({
      subjectCode:String(item.SubjectCode||''),
      subject:String(item.SubjectName||''),
      caeType:Number(item.CAEType)||null,
      marks:item.Marks==null?null:Number(item.Marks),
      result:String(item.Result||'').toUpperCase()
    })).filter(item=>item.subjectCode&&item.caeType);
    res.json({mode:'erp',status:'ok',academicYear,semester,cae});
  }catch(err){
    console.error('[CAE] Retrieval error:',err.message);
    res.status(502).json({status:'unavailable',error:'Unable to reach the ERP CAE service right now.'});
  }
});
// ---------- Semester examination results (student + batch + academic-period aware) ----------
app.get('/api/student/semester-results',session,async(req,res)=>{
  const s=req.portalSession;
  if(s.mode==='demo')return res.json({mode:'demo',status:'demo',semesters:[],message:'Demo accounts do not contain official examination records.'});
  if(s.mode!=='erp')return res.status(401).json({error:'Link your ERP session first.'});
  const registerNumber=String(s.registerNumber||'').trim();
  if(!registerNumber)return res.status(422).json({status:'missing-context',error:'Register number is missing from the ERP session.'});
  const history=Array.isArray(s.academicHistory)?s.academicHistory:[];
  if(!history.length)return res.json({mode:'erp',status:'missing-academic-history',semesters:[],message:'The ERP profile did not provide academic-period records. Results were not requested using guessed year or semester values.'});
  const currentSemester=Number(s.semester||0);
  // Use every academic period explicitly supplied by this student's ERP profile.
  // Do not infer a batch, academic year, semester sequence or examination month.
  const periods=history.slice()
    .sort((a,b)=>a.academicYear.localeCompare(b.academicYear)||a.semester-b.semester||a.academicMonthId-b.academicMonthId);
  const unique=[...new Map(periods.map(p=>[[p.semester,p.academicYear,p.academicMonthId].join('|'),p])).values()];
  if(!unique.length)return res.json({mode:'erp',status:'no-completed-periods',semesters:[],message:'No semester periods were found for this student.'});
  const headers={'Content-Type':'application/json','Accept':'application/json','Authorization':`Bearer ${s.accessToken}`};
  const results=[];
  const failures=[];
  for(const period of unique){
    const cacheKey=`${req.portalSessionId}:semesterResult:${period.semester}:${period.academicYear}:${period.academicMonthId}`;
    const hit=cache.get(cacheKey);
    if(hit&&hit.t>Date.now()-60000){results.push(...hit.v);continue;}
    try{
      const upstream=await fetch(ERP+'/erp/api/v1.0/ResultMark/studentResult',{
        method:'POST',headers,
        body:JSON.stringify({RegisterNumber:registerNumber,AcademicMonthId:period.academicMonthId,AcademicYear:period.academicYear,Semester:period.semester}),
        signal:AbortSignal.timeout(20000)
      });
      const payload=await upstream.json().catch(()=>null);
      if(upstream.status===401||upstream.status===403){sessions.delete(req.portalSessionId);return res.status(401).json({error:'ERP session expired. Sign in on the ERP and link again.'});}
      if(!upstream.ok||payload?.status!==true){failures.push({semester:period.semester,academicYear:period.academicYear,academicMonthId:period.academicMonthId});continue;}
      const response=payload.responseData||{};
      const rows=Array.isArray(response.SemResult)?response.SemResult:[];
      // The ERP response is scoped by the requested academic period. A subject's
      // own row.Semester can remain its original/first registration semester even
      // when the cleared attempt is returned in a later semester result period.
      // Therefore group rows by the requested period, and do not reject a cleared
      // attempt merely because row.Semester differs from period.semester.
      const matching=rows.filter(row=>
        (!row.AcademicYear||String(row.AcademicYear)===period.academicYear) &&
        (row.AcademicMonthId==null||Number(row.AcademicMonthId)===period.academicMonthId))
        .map(row=>({
          semester:period.semester,academicYear:period.academicYear,academicMonthId:period.academicMonthId,
          subjectCode:String(row.SubjectCode||''),subject:String(row.SubjectName||''),
          internalMark:row.InternalMark==null?null:Number(row.InternalMark),
          externalMark:row.ExternalMark==null?null:Number(row.ExternalMark),
          totalMark:row.TotalMark==null?null:Number(row.TotalMark),
          result:String(row.Result||'').trim().toUpperCase()
        })).filter(row=>row.subject||row.subjectCode);
      cache.set(cacheKey,{t:Date.now(),v:matching});
      results.push(...matching);
    }catch(err){
      console.error('[SEMESTER RESULTS] Retrieval failed:',{semester:period.semester,academicYear:period.academicYear,message:err.message});
      failures.push({semester:period.semester,academicYear:period.academicYear,academicMonthId:period.academicMonthId});
    }
  }
  const semesters=[...new Map(results.map(r=>[[r.semester,r.academicYear,r.academicMonthId].join('|'),{
    semester:r.semester,academicYear:r.academicYear,academicMonthId:r.academicMonthId,
    period:academicPeriodLabel(r.academicMonthId),subjects:[]
  }])).values()];
  for(const semester of semesters){semester.subjects=results.filter(r=>r.semester===semester.semester&&r.academicYear===semester.academicYear&&r.academicMonthId===semester.academicMonthId);}
  semesters.sort((a,b)=>a.academicYear.localeCompare(b.academicYear)||a.academicMonthId-b.academicMonthId||a.semester-b.semester);
  res.json({mode:'erp',status:failures.length?(results.length?'partial':'unavailable'):'ok',semesters,failedPeriods:failures});
});

app.get('/api/student/academics',session,(q,r)=>erpData('academics',q,r));

// Academic assistant: API key stays on the backend. The ERP access token and
// student profile are deliberately not included in the AI request.
app.post('/api/ai/chat',session,rateLimit({windowMs:60*1000,limit:20,standardHeaders:true,legacyHeaders:false}),async(req,res)=>{
  const apiKey=process.env.GEMINI_API_KEY;
  if(!apiKey)return res.status(503).json({error:'SIST AI is not configured. Add GEMINI_API_KEY to backend/.env and restart the backend.'});
  const message=String(req.body?.message||'').trim();
  if(!message||message.length>4000)return res.status(400).json({error:'Enter a message up to 4,000 characters.'});
  const history=Array.isArray(req.body?.history)?req.body.history.slice(-8).map(m=>({role:m?.role==='assistant'?'model':'user',parts:[{text:String(m?.content||'').slice(0,4000)}]})).filter(m=>m.parts[0].text):[];
  // Allowlist and bound the academic context. Never forward profile, register number,
  // ERP access token, cookies, contact details, or arbitrary client-supplied objects.
  const raw=req.body?.academicContext&&typeof req.body.academicContext==='object'?req.body.academicContext:{};
  const text=(v,n=120)=>String(v??'').slice(0,n);
  const num=v=>Number.isFinite(Number(v))?Number(v):null;
  const academicContext={
    attendance:{overallPercentage:num(raw.attendance?.overallPercentage),subjects:Array.isArray(raw.attendance?.subjects)?raw.attendance.subjects.slice(0,80).map(x=>({subject:text(x.subject),code:text(x.code,40),present:num(x.present),total:num(x.total),percentage:num(x.percentage)})):[]},
    semesterResults:Array.isArray(raw.semesterResults)?raw.semesterResults.slice(0,12).map(g=>({semester:text(g.semester,12),academicYear:text(g.academicYear,20),period:text(g.period,40),subjects:Array.isArray(g.subjects)?g.subjects.slice(0,80).map(x=>({subject:text(x.subject),code:text(x.code,40),internal:num(x.internal),external:num(x.external),total:num(x.total),result:text(x.result,20)})):[]})):[],
    caeResults:Array.isArray(raw.caeResults)?raw.caeResults.slice(0,100).map(x=>({subject:text(x.subject),code:text(x.code,40),assessment:text(x.assessment,12),marks:num(x.marks),result:text(x.result,20)})):[],
    timetable:Array.isArray(raw.timetable)?raw.timetable.slice(0,60).map(x=>({day:text(x.day,20),subject:text(x.subject),code:text(x.code,40),from:text(x.from,20),to:text(x.to,20),hour:text(x.hour,20),type:text(x.type,12)})):[]
  };
  const systemPrompt=`You are SIST AI, the academic assistant inside the Sathyabama student portal. Help with subject explanations, step-by-step problem solving, exam preparation, study plans, attendance calculations, CAE interpretation, semester-result interpretation, arrear history, and GPA/CGPA mathematics.

The following JSON is the only live academic context currently supplied by the portal for this turn. Use it when relevant, and clearly say when a field or record is missing. Do not infer missing marks, credits, grades, attendance rules, or official university policies.
${JSON.stringify(academicContext)}

Rules: distinguish a subject's curriculum semester from the academic period in which an arrear-clearing attempt was published. A later PASS for the same subject code clears an earlier RA/FAIL for current arrear status, while both attempts remain in history. When comparing attempts, prefer the later academic period in the supplied semester history, not merely the subject's own semester label. Do not claim official CGPA unless provided; calculate estimates only when credit weights and grade-point rules are known, otherwise state assumptions. Explain formulas and show working for calculations. For exam answers, structure by marks requested (for example 2/5/10/13 marks) and include diagrams as text descriptions where useful. Never claim to access ERP live; the supplied context is a snapshot loaded by the portal. Never request or reveal passwords, OTPs, cookies, access tokens, register numbers, or personal contact details. Be supportive, concise, and accurate.`;
  try{
    const contents=[
      ...history.slice(0,-1),
      {role:'user',parts:[{text:message}]}
    ];
    const model=String(process.env.GEMINI_MODEL||'gemini-2.5-flash').trim();
    const response=await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,{
      method:'POST',
      headers:{'Content-Type':'application/json','x-goog-api-key':apiKey},
      body:JSON.stringify({
        systemInstruction:{parts:[{text:systemPrompt}]},
        contents,
        generationConfig:{temperature:0.35,maxOutputTokens:2048}
      }),
      signal:AbortSignal.timeout(45000)
    });
    const payload=await response.json().catch(()=>null);
    if(!response.ok){
      const providerMessage=payload?.error?.message||'unknown provider error';
      console.error('Gemini provider error:',response.status,providerMessage);
      if(response.status===400||response.status===401||response.status===403||response.status===404||response.status===429){
        return res.status(502).json({error:`Gemini could not complete the request (HTTP ${response.status}). Check the API key, model name and AI Studio quota. See the backend terminal for details.`});
      }
      return res.status(502).json({error:'Gemini could not complete the request. Check the backend terminal for details.'});
    }
    const reply=payload?.candidates?.[0]?.content?.parts?.map(part=>part.text||'').join('').trim();
    if(!reply)return res.status(502).json({error:'Gemini returned no text. The response may have been blocked or the model may have stopped unexpectedly.'});
    res.json({reply});
  }catch(err){
    console.error('Gemini chat error:',err.message);
    res.status(502).json({error:'Could not reach Gemini right now. Check your internet connection and backend terminal.'});
  }
});

app.post('/api/auth/logout',(req,res)=>{const id=cookie(req);if(id)sessions.delete(id);res.clearCookie(cookieName,{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',path:'/'});res.json({ok:true})});
// Last-resort safety net: whatever goes wrong anywhere above, always answer with
// JSON (never Express's default HTML error page) and print the real error to this
// terminal — check here first whenever the browser shows an unexplained 500.
app.use((req,res)=>res.status(404).json({error:'Not found.'}));
app.use((err,req,res,_next)=>{console.error('Unhandled error on',req.method,req.path,':',err);if(!res.headersSent)res.status(500).json({error:'Unexpected server error. Check the backend terminal for details.'})});
process.on('unhandledRejection',(err)=>console.error('Unhandled promise rejection:',err));

app.listen(PORT,'0.0.0.0',()=>console.log(`Portal API running on http://localhost:${PORT}`));

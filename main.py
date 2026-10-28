"""FAKELENS API backend. MVP: JWT auth, audits, guidelines, assets, settings, review workflow, analytics."""
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional
import sqlite3, os, json, uuid, re, hashlib, secrets, shutil

try:
    from jose import jwt, JWTError
except ImportError:
    jwt = None
    JWTError = Exception

BASE=Path(__file__).resolve().parent
DB_PATH=Path(os.getenv('DATABASE_PATH',str(BASE/'fakelens.db')))
UPLOAD_DIR=Path(os.getenv('UPLOAD_DIR',str(BASE/'uploads')))
UPLOAD_DIR.mkdir(parents=True,exist_ok=True)
JWT_SECRET=os.getenv('JWT_SECRET','CHANGE_ME_BEFORE_PUBLIC_DEPLOYMENT_'+secrets.token_urlsafe(24))
JWT_ALGORITHM='HS256'; TOKEN_HOURS=int(os.getenv('TOKEN_HOURS','12'))
MAX_UPLOAD_BYTES=int(os.getenv('MAX_UPLOAD_MB','10'))*1024*1024

app=FastAPI(title='FAKELENS Backend API',version='1.0.0',description='Backend services for the FAKELENS brand governance prototype.')
origins=[x.strip() for x in os.getenv('CORS_ORIGINS','*').split(',') if x.strip()]
app.add_middleware(CORSMiddleware,allow_origins=['*'] if origins==['*'] else origins,allow_credentials=False,allow_methods=['*'],allow_headers=['*'])
security=HTTPBearer(auto_error=False)

DEFAULT_SETTINGS={'workspaceName':'FAKELENS Workspace','industry':'Technology & Digital Services','logoUrl':'','primaryColor':'#7C3AED','secondaryColor':'#C4B5FD','brandFont':'Inter','rules':{'brandConsistency':True,'factChecking':True,'claimsCompliance':True,'accessibility':True}}
DEFAULT_GUIDELINES=[
 {'id':'voice-and-tone','title':'Brand Voice & Tone','description':'Clear, helpful, transparent communication.','iconName':'Megaphone','attributes':['Professional','Clear','Helpful','Transparent'],'dos':['Use direct, concise and accessible vocabulary.','Keep claims transparent and evidence-backed.'],'donts':['Avoid unverified superlatives or exaggerated guarantees.','Avoid aggressive or deceptive sales language.'],'examples':{'onBrand':'Clear, verifiable brand communication.','offBrand':'Guaranteed 1000% instant results!'}},
 {'id':'messaging','title':'Messaging & Positioning','description':'Accurate value propositions and positioning.','iconName':'Target','attributes':['Accurate','Value-Focused'],'dos':['Describe capabilities that can be demonstrated.'],'donts':['Do not make unsupported competitive claims.'],'examples':{'onBrand':'Designed to help teams review content.','offBrand':'The only product that guarantees success.'}},
 {'id':'accessibility','title':'Accessibility','description':'Basic readability and inclusive communication.','iconName':'Accessibility','attributes':['Readable','Inclusive'],'dos':['Prefer plain language and descriptive labels.'],'donts':['Avoid excessive uppercase text.'],'examples':{'onBrand':'Review your content.','offBrand':'BUY NOW!!!'}}]

# Database helpers
def db():
    c=sqlite3.connect(DB_PATH,timeout=30); c.row_factory=sqlite3.Row; return c
def now(): return datetime.now(timezone.utc).isoformat()
def j(v): return json.dumps(v,ensure_ascii=False)
def readj(v,default=None):
    try: return json.loads(v) if v else (default if default is not None else {})
    except Exception: return default if default is not None else {}
def pw_hash(password,salt=None):
    salt=salt or secrets.token_hex(16); digest=hashlib.pbkdf2_hmac('sha256',password.encode(),salt.encode(),200000).hex(); return salt+'$'+digest
def pw_ok(password,stored):
    try:
        salt,digest=stored.split('$',1); return secrets.compare_digest(pw_hash(password,salt).split('$',1)[1],digest)
    except Exception: return False

def init_db():
    DB_PATH.parent.mkdir(parents=True,exist_ok=True)
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,name TEXT NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'creator',created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1),data_json TEXT NOT NULL,updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS guidelines(id TEXT PRIMARY KEY,data_json TEXT NOT NULL,updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audits(id TEXT PRIMARY KEY,title TEXT NOT NULL,filename TEXT,content_type TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,status TEXT NOT NULL,score INTEGER NOT NULL,summary TEXT NOT NULL,issues_json TEXT NOT NULL,fixes_json TEXT NOT NULL,checklist_json TEXT NOT NULL,notes TEXT,created_by TEXT,reviewer_id TEXT,review_comment TEXT,asset_path TEXT);
        CREATE TABLE IF NOT EXISTS comments(id TEXT PRIMARY KEY,audit_id TEXT NOT NULL,user_id TEXT,author TEXT NOT NULL,body TEXT NOT NULL,created_at TEXT NOT NULL,FOREIGN KEY(audit_id) REFERENCES audits(id));
        CREATE TABLE IF NOT EXISTS assets(id TEXT PRIMARY KEY,name TEXT NOT NULL,content_type TEXT NOT NULL,size INTEGER NOT NULL,path TEXT NOT NULL,created_at TEXT NOT NULL,created_by TEXT);
        CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,audit_id TEXT,actor_id TEXT,action TEXT NOT NULL,details TEXT,created_at TEXT NOT NULL);
        """)
        if not c.execute('SELECT id FROM settings WHERE id=1').fetchone(): c.execute('INSERT INTO settings VALUES(1,?,?)',(j(DEFAULT_SETTINGS),now()))
        if not c.execute('SELECT id FROM guidelines LIMIT 1').fetchone():
            for g in DEFAULT_GUIDELINES: c.execute('INSERT INTO guidelines VALUES(?,?,?)',(g['id'],j(g),now()))

def log_event(audit_id,actor,action,details=''):
    with db() as c: c.execute('INSERT INTO events VALUES(?,?,?,?,?,?)',(str(uuid.uuid4()),audit_id,actor,action,details,now()))

@app.on_event('startup')
def startup(): init_db()

# Auth
class RegisterIn(BaseModel):
    name:str=Field(min_length=2,max_length=100); email:EmailStr; password:str=Field(min_length=8,max_length=128)
class LoginIn(BaseModel): email:EmailStr; password:str
class UserOut(BaseModel): id:str; name:str; email:str; role:str

def token_for(user):
    if jwt is None: raise HTTPException(500,'Backend dependencies missing. Install requirements.txt.')
    return jwt.encode({'sub':user['id'],'email':user['email'],'role':user['role'],'exp':datetime.now(timezone.utc)+timedelta(hours=TOKEN_HOURS)},JWT_SECRET,algorithm=JWT_ALGORITHM)
def current_user(creds:HTTPAuthorizationCredentials=Depends(security)):
    if not creds: return None
    if jwt is None: raise HTTPException(500,'JWT dependency missing')
    try:
        payload=jwt.decode(creds.credentials,JWT_SECRET,algorithms=[JWT_ALGORITHM]); uid=payload.get('sub')
    except JWTError: raise HTTPException(401,'Invalid or expired token')
    with db() as c: row=c.execute('SELECT id,email,name,role,created_at FROM users WHERE id=?',(uid,)).fetchone()
    if not row: raise HTTPException(401,'User not found')
    return dict(row)
def require_user(user=Depends(current_user)):
    if not user: raise HTTPException(401,'Sign in required')
    return user
def require_reviewer(user=Depends(require_user)):
    if user['role'] not in ('reviewer','manager','admin'): raise HTTPException(403,'Reviewer or manager role required')
    return user

@app.post('/api/auth/register')
def register(data:RegisterIn):
    uid=str(uuid.uuid4()); role='creator'
    with db() as c:
        if c.execute('SELECT id FROM users WHERE email=?',(data.email.lower(),)).fetchone(): raise HTTPException(409,'Email already registered')
        c.execute('INSERT INTO users VALUES(?,?,?,?,?,?)',(uid,data.email.lower(),data.name,pw_hash(data.password),role,now()))
    user={'id':uid,'email':data.email.lower(),'name':data.name,'role':role}
    return {'accessToken':token_for(user),'tokenType':'bearer','user':user}
@app.post('/api/auth/login')
def login(data:LoginIn):
    with db() as c: row=c.execute('SELECT * FROM users WHERE email=?',(data.email.lower(),)).fetchone()
    if not row or not pw_ok(data.password,row['password_hash']): raise HTTPException(401,'Email or password is incorrect')
    user={'id':row['id'],'email':row['email'],'name':row['name'],'role':row['role']}
    return {'accessToken':token_for(user),'tokenType':'bearer','user':user}
@app.get('/api/auth/me')
def me(user=Depends(require_user)): return user

@app.get('/')
def root(): return {'name':'FAKELENS API','version':'1.0.0','docs':'/docs','health':'/api/health'}
@app.get('/api/health')
def health(): return {'connected':True,'version':'1.0.0','aiEngineReady':bool(os.getenv('OPENAI_API_KEY')),'mode':'rule-based checks' if not os.getenv('OPENAI_API_KEY') else 'AI key configured; AI integration is not enabled in this starter','message':'API is responding. Findings are heuristic and require human review.'}

# Audit engine
def analyse_text(text):
    issues=[]; checks=[]
    patterns=[(r'\b(guaranteed?|100% guaranteed|risk[- ]free|zero risk|instant results?)\b','Claims compliance','High','Potentially absolute or guaranteed claim. Verify approved evidence before publication.','Replace absolute wording with a specific, supportable statement and attach evidence.'),(r'\b(best|#1|number one|world[- ]class|unmatched|revolutionary)\b','Unsupported superlative','Medium','A superlative may require substantiation or approved brand wording.','Add supporting evidence or use a more specific descriptive claim.'),(r'\b(act now|last chance|buy now or regret|limited time only)\b','Tone & pressure','Low','High-pressure wording may conflict with a transparent, helpful brand voice.','Use a clear call to action without pressure.')]
    for i,(pat,cat,sev,desc,sugg) in enumerate(patterns,1):
        found=sorted(set(m.group(0) for m in re.finditer(pat,text,re.I)))
        if found: issues.append({'id':f'issue-{i}','category':cat,'severity':sev,'description':desc,'evidence':', '.join(found[:5]),'suggestion':sugg}); checks.append({'id':f'check-{i}','name':cat,'status':'Failed' if sev=='High' else 'Warning','details':desc})
        else: checks.append({'id':f'check-{i}','name':cat,'status':'Passed','details':'No matching wording found by this heuristic.'})
    caps=len(re.findall(r'\b[A-Z]{4,}\b',text))
    if caps>=4: issues.append({'id':'issue-uppercase','category':'Readability','severity':'Low','description':'Several all-caps words may reduce readability.','evidence':f'{caps} all-caps words detected','suggestion':'Use sentence case except for approved acronyms.'})
    checks.append({'id':'check-readability','name':'Readability','status':'Warning' if caps>=4 else 'Passed','details':'All-caps heuristic check.'})
    score=max(0,100-sum({'High':30,'Medium':15,'Low':7}[x['severity']] for x in issues)); status='Rejected' if any(x['severity']=='High' for x in issues) else ('Needs Fix' if issues else 'Approved')
    return score,status,issues,checks

def audit_out(r):
    return {'id':r['id'],'auditId':r['id'],'title':r['title'],'type':'PDF' if (r['filename'] or '').lower().endswith('.pdf') else 'Marketing Copy','date':r['created_at'],'relativeTime':r['created_at'],'status':r['status'],'complianceScore':r['score'],'complianceStatus':'On Brand' if r['score']>=85 else ('Needs Review' if r['score']>=60 else 'Off Brand'),'summaryText':r['summary'],'issues':readj(r['issues_json'],[]),'suggestedFixes':readj(r['fixes_json'],[]),'checklist':readj(r['checklist_json'],[]),'filename':r['filename'],'notes':r['notes'],'reviewComment':r['review_comment'],'reviewerId':r['reviewer_id']}
class ReviewIn(BaseModel): action:str=Field(pattern='^(approve|reject|request_changes)$'); comment:str=Field(default='',max_length=3000)
class CommentIn(BaseModel): body:str=Field(min_length=1,max_length=3000)

@app.post('/api/audits')
async def create_audit(file:UploadFile=File(...),notes:str=Form(''),brandId:Optional[str]=Form(None),user=Depends(require_user)):
    raw=await file.read()
    if len(raw)>MAX_UPLOAD_BYTES: raise HTTPException(413,f'File exceeds {MAX_UPLOAD_BYTES//1024//1024} MB limit')
    filename=Path(file.filename or 'upload').name; suffix=Path(filename).suffix.lower(); ct=file.content_type or 'application/octet-stream'; text=''
    if suffix in ('.txt','.md','.csv','.json','.html','.xml') or ct.startswith('text/') or 'json' in ct: text=raw.decode('utf-8',errors='replace')[:200000]
    score,status,issues,checks=analyse_text(text)
    if not text.strip():
        issues.append({'id':'issue-extraction','category':'Content extraction','severity':'Medium','description':'This backend currently cannot extract text from this file type.','evidence':filename,'suggestion':'Use .txt, .md, .csv or .json for current text checks; PDF/image OCR is not implemented.'}); checks.append({'id':'check-extraction','name':'Content extraction','status':'Warning','details':'No text extracted.'}); score=min(score,85); status='Needs Fix'
    aid=str(uuid.uuid4()); timestamp=now(); fixes=[{'id':f'fix-{i+1}','type':'claim','title':'Suggested correction','description':x.get('suggestion','Review finding.'),'applied':False} for i,x in enumerate(issues)]
    summary=f'Rule-based prototype check completed: {len(issues)} finding(s). This is not verified fact-checking or a real AI assessment.'
    with db() as c: c.execute('INSERT INTO audits VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(aid,filename,filename,ct,timestamp,timestamp,status,score,summary,j(issues),j(fixes),j(checks),notes,user['id'],None,None,None))
    log_event(aid,user['id'],'created','Audit created')
    return {'auditId':aid,'status':'completed','estimatedDurationMs':100,'audit':{'id':aid,'title':filename,'type':'Marketing Copy','date':timestamp,'relativeTime':timestamp,'status':status,'complianceScore':score,'complianceStatus':'On Brand' if score>=85 else ('Needs Review' if score>=60 else 'Off Brand'),'summaryText':summary,'issues':issues,'suggestedFixes':fixes,'checklist':checks,'filename':filename}}
@app.get('/api/audits')
def list_audits(page:int=1,pageSize:int=20,search:Optional[str]=None,type:Optional[str]=None,timeRange:Optional[str]=None,user=Depends(require_user)):
    page=max(1,page); pageSize=min(max(1,pageSize),100)
    with db() as c: rows=c.execute('SELECT * FROM audits ORDER BY created_at DESC').fetchall()
    items=[audit_out(r) for r in rows]
    if search: items=[x for x in items if search.lower() in (x['title']+' '+x['summaryText']).lower()]
    if type: items=[x for x in items if x['type'].lower()==type.lower()]
    total=len(items); return {'items':items[(page-1)*pageSize:page*pageSize],'total':total,'page':page,'totalPages':max(1,(total+pageSize-1)//pageSize)}
@app.get('/api/audits/{audit_id}')
def get_audit(audit_id:str,user=Depends(require_user)):
    with db() as c: r=c.execute('SELECT * FROM audits WHERE id=?',(audit_id,)).fetchone()
    if not r: raise HTTPException(404,'Audit not found')
    return audit_out(r)
@app.post('/api/audits/{audit_id}/review')
def review_audit(audit_id:str,data:ReviewIn,user=Depends(require_reviewer)):
    status={'approve':'Approved','reject':'Rejected','request_changes':'Needs Fix'}[data.action]
    with db() as c:
        r=c.execute('SELECT id FROM audits WHERE id=?',(audit_id,)).fetchone()
        if not r: raise HTTPException(404,'Audit not found')
        c.execute('UPDATE audits SET status=?,updated_at=?,reviewer_id=?,review_comment=? WHERE id=?',(status,now(),user['id'],data.comment,audit_id))
    log_event(audit_id,user['id'],data.action,data.comment); return {'ok':True,'auditId':audit_id,'status':status,'comment':data.comment}
@app.get('/api/audits/{audit_id}/comments')
def get_comments(audit_id:str,user=Depends(require_user)):
    with db() as c:
        if not c.execute('SELECT id FROM audits WHERE id=?',(audit_id,)).fetchone(): raise HTTPException(404,'Audit not found')
        rows=c.execute('SELECT * FROM comments WHERE audit_id=? ORDER BY created_at',(audit_id,)).fetchall()
    return {'items':[dict(x) for x in rows]}
@app.post('/api/audits/{audit_id}/comments')
def add_comment(audit_id:str,data:CommentIn,user=Depends(require_user)):
    cid=str(uuid.uuid4()); ts=now()
    with db() as c:
        if not c.execute('SELECT id FROM audits WHERE id=?',(audit_id,)).fetchone(): raise HTTPException(404,'Audit not found')
        c.execute('INSERT INTO comments VALUES(?,?,?,?,?,?)',(cid,audit_id,user['id'],user['name'],data.body,ts))
    log_event(audit_id,user['id'],'commented',data.body); return {'id':cid,'auditId':audit_id,'author':user['name'],'body':data.body,'created_at':ts}
@app.get('/api/audits/{audit_id}/events')
def audit_events(audit_id:str,user=Depends(require_user)):
    with db() as c: rows=c.execute('SELECT * FROM events WHERE audit_id=? ORDER BY created_at',(audit_id,)).fetchall()
    return {'items':[dict(x) for x in rows]}

# Guidelines/settings
@app.get('/api/guidelines')
def get_guidelines(user=Depends(require_user)):
    with db() as c: rows=c.execute('SELECT data_json FROM guidelines ORDER BY id').fetchall()
    return {'items':[readj(r['data_json']) for r in rows]}
class GuidelineUpdate(BaseModel): title:Optional[str]=None; description:Optional[str]=None; dos:Optional[list[str]]=None; donts:Optional[list[str]]=None; attributes:Optional[list[str]]=None; examples:Optional[dict]=None
@app.patch('/api/guidelines/{gid}')
def update_guideline(gid:str,data:GuidelineUpdate,user=Depends(require_reviewer)):
    with db() as c:
        r=c.execute('SELECT data_json FROM guidelines WHERE id=?',(gid,)).fetchone()
        if not r: raise HTTPException(404,'Guideline not found')
        item=readj(r['data_json']); item.update(data.model_dump(exclude_none=True)); c.execute('UPDATE guidelines SET data_json=?,updated_at=? WHERE id=?',(j(item),now(),gid))
    return item
@app.get('/api/settings')
def get_settings(user=Depends(require_user)):
    with db() as c: r=c.execute('SELECT data_json FROM settings WHERE id=1').fetchone()
    return readj(r['data_json'])
class SettingsUpdate(BaseModel): workspaceName:Optional[str]=None; industry:Optional[str]=None; logoUrl:Optional[str]=None; primaryColor:Optional[str]=None; secondaryColor:Optional[str]=None; brandFont:Optional[str]=None; rules:Optional[dict]=None
@app.patch('/api/settings')
def update_settings(data:SettingsUpdate,user=Depends(require_reviewer)):
    with db() as c:
        r=c.execute('SELECT data_json FROM settings WHERE id=1').fetchone(); item=readj(r['data_json']); item.update(data.model_dump(exclude_none=True)); c.execute('UPDATE settings SET data_json=?,updated_at=? WHERE id=1',(j(item),now()))
    return item

# Assets: persisted locally, not object storage
@app.post('/api/assets')
async def upload_asset(file:UploadFile=File(...),user=Depends(require_reviewer)):
    raw=await file.read()
    if len(raw)>MAX_UPLOAD_BYTES: raise HTTPException(413,'File too large')
    aid=str(uuid.uuid4()); safe=Path(file.filename or 'asset').name; dest=UPLOAD_DIR/f'{aid}_{safe}'; dest.write_bytes(raw)
    with db() as c: c.execute('INSERT INTO assets VALUES(?,?,?,?,?,?,?)',(aid,safe,file.content_type or 'application/octet-stream',len(raw),str(dest),now(),user['id']))
    return {'id':aid,'name':safe,'type':file.content_type or 'application/octet-stream','size':len(raw),'url':f'/api/assets/{aid}/download'}
@app.get('/api/assets')
def list_assets(user=Depends(require_user)):
    with db() as c: rows=c.execute('SELECT * FROM assets ORDER BY created_at DESC').fetchall()
    used=sum(r['size'] for r in rows)
    return {'logos':[{'id':r['id'],'name':r['name'],'url':f"/api/assets/{r['id']}/download",'type':r['content_type']} for r in rows if r['content_type'].startswith('image/')], 'templates':[], 'items':[{'id':r['id'],'name':r['name'],'url':f"/api/assets/{r['id']}/download",'type':r['content_type'],'size':r['size']} for r in rows], 'storageUsedBytes':used,'storageLimitBytes':100*1024*1024}
@app.get('/api/assets/{asset_id}/download')
def download_asset(asset_id:str,user=Depends(require_user)):
    from fastapi.responses import FileResponse
    with db() as c: r=c.execute('SELECT * FROM assets WHERE id=?',(asset_id,)).fetchone()
    if not r or not Path(r['path']).exists(): raise HTTPException(404,'Asset not found')
    return FileResponse(r['path'],media_type=r['content_type'],filename=r['name'])

@app.get('/api/analytics')
def analytics(dateRange:str='30d',user=Depends(require_user)):
    with db() as c: rows=c.execute('SELECT status,score,created_at,issues_json FROM audits ORDER BY created_at').fetchall()
    dist={}; trends=[]
    for r in rows:
        trends.append({'date':r['created_at'][:10],'score':r['score']})
        for issue in readj(r['issues_json'],[]): dist[issue.get('category','Other')]=dist.get(issue.get('category','Other'),0)+1
    total=len(rows); approved=sum(r['status']=='Approved' for r in rows); rejected=sum(r['status']=='Rejected' for r in rows); needs=sum(r['status']=='Needs Fix' for r in rows)
    return {'hasData':total>0,'totalAudits':total,'approved':approved,'needsFix':needs,'rejected':rejected,'complianceTrends':trends,'issueDistribution':[{'category':k,'count':v,'color':'#7C3AED'} for k,v in dist.items()]}

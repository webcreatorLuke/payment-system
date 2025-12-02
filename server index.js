// Serve the client from the same origin
const path = require('path');
app.use(express.static(path.join(__dirname, '../client')));

app.get('/hosted/fields', (req, res) => {
  const parentOrigin = `${req.protocol}://${req.headers.host}`; // same origin
  res.setHeader('Content-Type', 'text/html');
  res.send(`
<!doctype html>
<html>
<head><meta charset="utf-8" /><title>Hosted Fields</title>
<style>body{font-family:system-ui,sans-serif;margin:0;padding:12px}.row{margin-bottom:8px}input{padding:8px;border:1px solid #d1d5db;border-radius:6px;width:100%}.error{color:#b91c1c;font-size:12px}button{padding:8px 12px;border:none;background:#111827;color:#fff;border-radius:6px;cursor:pointer}</style>
</head>
<body>
  <div class="row"><input id="pan" inputmode="numeric" autocomplete="off" placeholder="Card number" /></div>
  <div class="row" style="display:flex; gap:8px;">
    <input id="exp" inputmode="numeric" placeholder="MM/YY" />
    <input id="cvv" inputmode="numeric" placeholder="CVV" />
  </div>
  <div id="err" class="error"></div>
  <button id="tokenize">Tokenize</button>
<script>
  const parentOrigin = '${parentOrigin}';
  const errEl = document.getElementById('err');
  const postParent = (type, payload) => parent.postMessage({ type, payload }, parentOrigin);

  function luhnOk(number){const n=number.replace(/\\D/g,'');let sum=0,alt=false;for(let i=n.length-1;i>=0;i--){let d=parseInt(n[i],10);if(alt){d*=2;if(d>9)d-=9}sum+=d;alt=!alt}return sum%10===0}

  async function tokenize(){
    errEl.textContent='';
    const pan=(document.getElementById('pan').value||'').replace(/\\D/g,'');
    const exp=(document.getElementById('exp').value||'');
    const cvv=(document.getElementById('cvv').value||'');
    if(pan.length<13||pan.length>19||!luhnOk(pan)){errEl.textContent='Invalid card number';postParent('error',{message:'Invalid card number'});return}
    const [mm,yy]=exp.split('/');const expMonth=parseInt(mm,10);const expYear=parseInt('20'+(yy||''),10);
    if(!expMonth||expMonth<1||expMonth>12||!expYear){errEl.textContent='Invalid expiration';postParent('error',{message:'Invalid expiration'});return}
    if(!cvv||cvv.length<3||cvv.length>4){errEl.textContent='Invalid CVV';postParent('error',{message:'Invalid CVV'});return}
    try{
      const res = await fetch('/vault/tokenize',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pan,expMonth,expYear})});
      const data = await res.json();
      if(!res.ok){errEl.textContent=data.error||'Tokenization failed';postParent('error',{message:data.error||'Tokenization failed'});return}
      postParent('vaultedToken',{token:data.token});
    }catch(e){errEl.textContent='Network error';postParent('error',{message:'Network error'})}
  }
  document.getElementById('tokenize').addEventListener('click', tokenize);
  postParent('hostedReady',{});
  window.addEventListener('message', (evt)=>{ if(evt.origin!==parentOrigin) return; if(evt.data&&evt.data.type==='tokenize') tokenize(); });
</script>
</body></html>
  `);
});

const $ = id => document.getElementById(id);
let mode = 'live', token = '', busy = false, ready = false, signature = '';
function controls() {
  $('start').disabled = !ready || busy || (mode === 'live' && !$('interface').value);
  $('stop').disabled = !busy;
  for (const id of ['liveTab','fileTab','interface','duration','file']) $(id).disabled = busy;
}
function selectMode(next) {
  mode = next;
  $('liveForm').hidden = mode !== 'live'; $('fileForm').hidden = mode !== 'file';
  for (const [id,value] of [['liveTab','live'],['fileTab','file']]) {
    $(id).classList.toggle('selected', mode === value); $(id).setAttribute('aria-pressed', mode === value);
  }
  $('start').textContent = mode === 'live' ? 'Начать захват' : 'Анализировать файл'; controls();
}
$('liveTab').onclick = () => selectMode('live'); $('fileTab').onclick = () => selectMode('file');
async function request(path, body) {
  const response = await fetch(path, {method:'POST', headers:{'X-Logchecker-Token':token}, body});
  const data = await response.json(); if (!response.ok) throw Error(data.error); return data;
}
$('start').onclick = async () => {
  $('error').textContent = '';
  try {
    let body, path;
    if (mode === 'live') {
      const duration = Number($('duration').value);
      if (!Number.isInteger(duration) || duration < 1 || duration > 3600) throw Error('Длительность: от 1 до 3600 секунд.');
      body = JSON.stringify({interface:$('interface').value,duration}); path='/api/live';
    } else {
      body = $('file').files[0]; path='/api/pcap';
      if (!body) throw Error('Выберите файл PCAP или PCAPNG.');
      if (body.size > 64*1024*1024) throw Error('Максимальный размер — 64 МиБ.');
    }
    busy=true; controls(); await request(path,body); signature='';
  } catch(e) { $('error').textContent=e.message; busy=false; controls(); }
};
$('stop').onclick = async () => { try { await request('/api/stop',''); } catch(e) { $('error').textContent=e.message; } };
async function poll() {
  try {
    const response=await fetch('/api/state'); if(!response.ok) throw Error('Сервер недоступен');
    const s=await response.json(); busy=s.busy; controls();
    $('status').textContent={idle:'Готов к работе',running:'● Анализ идёт',done:'Анализ завершён',stopped:'Остановлено',error:'Ошибка анализа'}[s.state];
    $('packets').textContent=s.stats.packets.toLocaleString('ru');
    $('bytes').textContent=s.stats.bytes<1024 ? s.stats.bytes+' Б' : (s.stats.bytes/1024).toFixed(1)+' КиБ';
    $('flows').textContent=s.stats.tracked_flows;
    $('count').textContent=s.conversations.length+' групп соединений';
    $('coverage').textContent=`Кадров без IP: ${s.stats.non_ip} · Ошибок разбора: ${s.malformed} · Вытеснено: ${s.stats.evicted_flows}. ${s.coverage}`;
    $('identityStatus').textContent=s.process_status;
    if(s.error) $('error').textContent=s.error;
    const sig=JSON.stringify([s.stats.packets,s.state,s.conversations[0]?.first]);
    if(sig!==signature) {
      const opened=new Set([...$('events').querySelectorAll('details[open]')].map(e=>e.dataset.frame));
      $('events').replaceChildren();
      const textNode=(tag,text,parent)=>{const n=document.createElement(tag);n.textContent=text;parent.append(n);return n;};
      for(const a of [...s.alerts].reverse()) {
        const box=document.createElement('article');box.className='alert-card';
        textNode('strong','Требует проверки: '+a.title,box);
        textNode('p',a.src+' → '+a.dst+' · '+a.explanation,box);
        textNode('p',a.action,box);
        textNode('small','Порты: '+a.ports.join(', ')+' · Пакеты: '+a.frames.join(', '),box);
        $('events').append(box);
      }
      if(!s.alerts.length && s.stats.packets) textNode('p','Признаков сканирования по текущему правилу не найдено. Это не проверка всех видов угроз.',$('events'));
      for(const e of s.conversations) {
        const d=document.createElement('details');d.dataset.frame=String(e.id);d.open=opened.has(d.dataset.frame);
        const endpoint=(ip,port)=>(ip.includes(':')?'['+ip+']':ip)+(port?':'+port:'');
        textNode('summary',endpoint(e.src,e.sport)+' ⇄ '+endpoint(e.dst,e.dport)+' · '+(e.tls?'TLS':e.protocol)+(e.attention?' · Сброс TCP':''),d);
        // Main explanation and volume are visible without opening the evidence.
        const brief=document.createElement('div');brief.className='conversation-brief';
        const apps=e.applications.length ? [...new Set(e.applications.map(a=>a.name))].join(' / ') : 'Приложение неизвестно';
        const sites=e.sites.length ? [...new Set(e.sites.map(s=>s.name))].join(' / ') :
          e.dns_candidates.length ? 'Возможно: '+[...new Set(e.dns_candidates.map(s=>s.name))].join(' / ') :
          e.dns.length ? 'DNS: '+e.dns.join(' / ') : 'Сайт не определён';
        textNode('h3',apps+' · '+sites,brief).className='identity-title';
        const sources=e.sites.length ? [...new Set(e.sites.map(s=>s.source))].join(', ') :
          e.dns_candidates.length ? 'Подсказка DNS — не подтверждено' : e.dns.length ? 'DNS-запрос, не посещение сайта' : 'Имя не видно в захвате';
        textNode('small',sources,brief).className='identity-source';
        textNode('p',e.explanation,brief);
        textNode('small',e.packets+' пакетов · '+(e.bytes/1024).toFixed(1)+' КиБ · '+(e.last-e.first).toFixed(1)+' с',brief);
        for(const text of [e.note,e.identity_note,`От первого адреса: ${e.sent} Б; обратно: ${e.received} Б`]) textNode('p',text,d);
        for(const a of e.applications) textNode('p',`${a.name} · PID ${a.pid} · ${endpoint(a.local_ip,a.local_port)} · ${a.source} · пакет #${a.frame}`,d);
        if(!e.applications.length) textNode('p','Процесс не найден: возможны короткий сокет, недостаточные права, другая машина или анализ PCAP.',d);
        for(const name of [...e.sites,...e.dns_candidates]) textNode('p',`${name.name} · ${name.source} · пакет #${name.frame}`+(name.confidence==='candidate'?' · связь предположительная, DNS действовал во время наблюдения':''),d);
        textNode('small',`Пакеты #${e.first_frame}–#${e.last_frame} (границы группы); признаки: `+Object.entries(e.evidence).map(([k,v])=>k+' #'+v).join(', '),d);
        const card=document.createElement('article');card.className='conversation';card.append(brief,d);$('events').append(card);
      }
      if(!s.conversations.length) textNode('p',busy?'Ожидаем трафик…':'Начните захват или выберите PCAP, чтобы увидеть соединения.',$('events'));
    }
    signature=sig;
  } catch(e) { $('status').textContent='Нет связи с локальным сервером'; }
  setTimeout(poll,700);
}
(async()=>{try{const r=await fetch('/api/config');const c=await r.json();token=c.token;ready=true;$('interface').replaceChildren();for(const i of c.interfaces){const o=document.createElement('option');o.value=i.id;o.textContent=i.label;$('interface').append(o);}if(c.error)$('error').textContent=c.error;controls();}catch(e){$('error').textContent=e.message;}poll();})();

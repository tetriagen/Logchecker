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
    $('count').textContent=s.total_events+' событий';
    $('coverage').textContent=`Кадров без IP: ${s.stats.non_ip} · Ошибок разбора: ${s.malformed} · Вытеснено соединений: ${s.stats.evicted_flows}`;
    if(s.error) $('error').textContent=s.error;
    const sig=JSON.stringify([s.total_events,s.events[0]?.time,s.state]);
    if(sig!==signature && s.events.length) {
      const opened=new Set([...$('events').querySelectorAll('details[open]')].map(e=>e.dataset.frame));
      $('events').replaceChildren();
      for(const e of [...s.events].reverse()) {
        const d=document.createElement('details'); d.dataset.frame=String(e.frame);d.open=opened.has(d.dataset.frame);
        const title=document.createElement('summary');title.textContent=e.explanation;d.append(title);
        for(const text of [`${e.src}:${e.sport} → ${e.dst}:${e.dport}`,e.note]) {const p=document.createElement('p');p.textContent=text;d.append(p);}
        const proof=document.createElement('small');proof.textContent=`Пакет #${e.frame} · ${e.protocol} · ${new Date(e.time*1000).toLocaleTimeString('ru')}`;d.append(proof);$('events').append(d);
      }
    } else if(!s.events.length && s.state!=='idle') { $('events').textContent=busy?'Ожидаем пакеты и события…':'Событий не обнаружено. Проверьте счётчики и выбранный источник.'; }
    signature=sig;
  } catch(e) { $('status').textContent='Нет связи с локальным сервером'; }
  setTimeout(poll,700);
}
(async()=>{try{const r=await fetch('/api/config');const c=await r.json();token=c.token;ready=true;$('interface').replaceChildren();for(const i of c.interfaces){const o=document.createElement('option');o.value=i.id;o.textContent=i.label;$('interface').append(o);}if(c.error)$('error').textContent=c.error;controls();}catch(e){$('error').textContent=e.message;}poll();})();

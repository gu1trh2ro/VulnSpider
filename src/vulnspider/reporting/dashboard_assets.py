"""Trusted, dependency-free navigation and presentation assets for v0.2."""

STYLE = """
:root{--paper:#f5f7fa;--ink:#192b3c;--muted:#627184;--accent:#087e8b;
 --line:#e1e8ed;--high:#b64d47;--medium:#987014;--low:#637588;
 --sqli:#b17a21;--xss:#7974c9;--bac:#208d91;--track:#eef2f6}
body{background:var(--paper);font-size:14px;word-break:keep-all}
a{color:inherit;text-decoration:none}button,input,select{font:inherit}
button,a,input,select,summary{-webkit-tap-highlight-color:transparent}
:focus-visible{outline:3px solid #0a98a6;outline-offset:4px}
summary:focus-visible{outline:3px solid #0a98a6!important;outline-offset:4px}
[hidden]{display:none!important}.skip-link{position:fixed;top:-70px;left:20px;z-index:50;
 background:white;padding:14px;border:2px solid var(--accent)}.skip-link:focus{top:10px}
.sidebar{position:fixed;inset:0 auto 0 0;width:224px;background:#102d3b;color:#b8ccd4;
 padding:32px 20px;display:flex;flex-direction:column;z-index:10}
.app-brand{display:flex;gap:11px;align-items:center;font-size:22px;font-weight:750;
 letter-spacing:-.7px;color:#f7ffff}.brand-mark{display:grid;place-items:center;width:36px;
 height:38px;background:#167b88;border:1px solid #3696a2;border-radius:12px;color:#dcffff}
.sidebar small{font-size:10px;letter-spacing:2px;display:block;margin:9px 0 39px 47px}
.nav-label{font-size:10px;letter-spacing:1.8px;color:#89a8b6;margin:8px 12px 12px}
.sidebar nav a{display:flex;gap:13px;align-items:center;padding:13px 14px;border-radius:8px;
 margin:5px 0;font-weight:550;font-size:13px}.sidebar nav a:hover{background:#1b4050}
.sidebar nav a[aria-current=page]{background:#1e4856;color:#b9f4ee}
.nav-icon{font-size:19px;line-height:1;width:20px;text-align:center}
.sidebar-bottom{margin-top:auto;padding:18px 12px 0;border-top:1px solid #30505d;
 font-size:12px;line-height:1.8}.sidebar-bottom strong{color:#dcebee}
.workspace{margin-left:224px;min-width:0}.topbar{height:76px;background:#fff;border-bottom:1px
 solid var(--line);display:flex;justify-content:space-between;align-items:center;padding:0 38px;
 gap:16px}.crumb{font-size:12px;color:var(--muted)}.crumb b{color:var(--ink);font-weight:600}
.top-actions{display:flex;gap:15px;align-items:center}.snapshot-badge{font-size:11px;color:#267b75;
 background:#eef8f5;border:1px solid #d5eae4;border-radius:20px;padding:5px 10px}
.button{display:inline-flex;align-items:center;justify-content:center;gap:8px;background:white;
 border:1px solid #d4dfe5;padding:10px 15px;border-radius:7px;cursor:pointer;font-size:12px;
 font-weight:650;color:var(--ink)}.button:hover{background:#f0f6f7}.button.primary{background:#087e8b;
 color:white;border-color:#087e8b}.button.primary:hover{background:#076b77}
.main-content{max-width:1510px;margin:auto;padding:32px 38px 48px}
.report-page{display:none}.report-page.overview{display:block}
.main-content:has(.report-page:target)>.overview{display:none}
.main-content>.report-page:target{display:block}
.enhanced .main-content>.report-page{display:none}.enhanced .main-content>.report-page.active{display:block}
.page-heading{display:flex;justify-content:space-between;gap:22px;align-items:center;margin-bottom:24px}
.eyebrow{font-size:10px;font-weight:700;letter-spacing:2px;color:var(--accent);margin-bottom:8px}
h1.page-title{font-size:29px;font-weight:750;letter-spacing:-1.2px;margin:0 0 8px;line-height:1.35}
.subtitle{color:var(--muted);font-size:13px;line-height:1.8;margin:0;max-width:770px}
.target-chip{display:inline-flex;gap:8px;align-items:center;font-family:var(--mono);font-size:11px;
 color:#4e6778;background:white;border:1px solid var(--line);border-radius:6px;padding:8px 11px;
 margin-top:13px;max-width:100%;overflow-wrap:anywhere}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;margin-bottom:22px}
.metric{padding:20px 22px;background:white;border:1px solid var(--line);border-radius:10px;
 box-shadow:0 3px 7px #192b3c03}.metric-label{font-size:12px;color:var(--muted);display:flex;
 justify-content:space-between}.metric-label span{color:#96a8b5}.metric-value{font-size:32px;
 font-weight:700;letter-spacing:-1.4px;margin:10px 0 6px;line-height:1}.metric-value small{
 font-size:12px;letter-spacing:0;color:var(--muted);margin-left:6px;font-weight:500}
.metric-note{font-size:11px;color:var(--muted)}.metric.accent{border-top:3px solid #188c94;
 padding-top:18px}.metric.accent .metric-value{color:var(--accent)}
.panel{background:white;border:1px solid var(--line);border-radius:11px;min-width:0;overflow:hidden}
.panel-head{display:flex;justify-content:space-between;align-items:center;gap:14px;padding:20px 23px 16px}
.panel h2{font-size:15px;margin:0;letter-spacing:-.3px}.panel-desc{font-size:11px;color:var(--muted);
 margin:5px 0 0;line-height:1.7}.panel-body{padding:0 23px 22px}.text-link{color:var(--accent);
 font-size:12px;font-weight:600;white-space:nowrap}.overview-grid{display:grid;
 grid-template-columns:minmax(0,2.15fr) minmax(250px,1fr);gap:20px;margin-bottom:22px}
.map-canvas{margin:0 16px 16px;border:1px solid #e8eef2;border-radius:8px;padding:22px;
 background-color:#fafcfd;background-image:radial-gradient(#dfe8ed 1px,transparent 1px);
 background-size:17px 17px;min-height:267px;display:flex;align-items:center;gap:30px}
.map-root{flex:0 0 95px;text-align:center;position:relative}.map-root-icon{margin:0 auto 9px;
 width:54px;height:54px;display:grid;place-items:center;font-size:25px;color:#087e8b;
 border:1px solid #a8d3d8;background:#eaf8f7;border-radius:16px;box-shadow:0 0 0 7px #f1f9fa}
.map-root strong{font-size:11px}.map-root small{display:block;color:var(--muted);font-size:10px;margin-top:3px}
.map-root:after{content:'';position:absolute;right:-30px;top:28px;width:33px;border-top:1px solid #bad0db}
.map-branches{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:13px;flex:1;
 min-width:0;position:relative;border-left:1px solid #bad0db;padding-left:22px}
.endpoint-node{position:relative;min-width:0;border:1px solid #dce6eb;border-radius:7px;
 background:white;box-shadow:0 2px 4px #17384c04;padding:11px}
.endpoint-node:before{content:'';position:absolute;left:-23px;top:22px;width:22px;border-top:1px solid #bad0db}
.node-path{font-family:var(--mono);font-size:10px;color:#526d7d;overflow-wrap:anywhere;
 border-bottom:1px solid #edf1f5;padding-bottom:7px;margin-bottom:7px}
.candidate-node{display:flex;gap:6px;align-items:center;justify-content:space-between;
 padding:5px 4px;border-radius:4px;font-size:11px}.candidate-node:hover{background:#edf7f7}
.candidate-node .node-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:130px}
.candidate-node strong{font-family:var(--mono);font-size:11px;color:var(--accent)}
.family-dot{width:7px;height:7px;display:inline-block;background:var(--muted);border-radius:50%;flex-shrink:0}
.family-dot.SQLI{background:var(--sqli)}.family-dot.REFLECTED_XSS{background:var(--xss)}
.family-dot.BROKEN_ACCESS_CONTROL{background:var(--bac)}
.map-legend{display:flex;gap:14px;flex-wrap:wrap;padding:0 23px 17px;color:var(--muted);font-size:10px}
.map-legend span{display:flex;gap:5px;align-items:center}.family-panel .donut-layout{justify-content:center}
.family-panel .donut-legend{font-size:11px}.family-panel .donut-svg{width:155px;height:155px}
.family-panel .donut{display:flex;flex-direction:column;align-items:center;gap:16px}
.family-panel .legend{width:100%;font-size:12px}.family-panel .chart-note{margin-top:14px}
.table-scroll{overflow:auto}.candidate-table{width:100%;border-collapse:collapse;white-space:nowrap}
.candidate-table th{text-align:left;background:#f9fbfc;color:#71818e;font-size:10px;font-weight:600;
 padding:11px 18px;border-block:1px solid #eaf0f3}.candidate-table td{padding:14px 18px;
 border-bottom:1px solid #edf1f4;font-size:12px}.candidate-table tr:last-child td{border-bottom:0}
.candidate-table td:first-child{color:#8b9aa6;font-family:var(--mono);font-size:11px;width:52px}
.location-link{display:block;font-family:var(--mono);font-size:12px;font-weight:600;
 max-width:330px;overflow:hidden;text-overflow:ellipsis}.location-sub{font-size:10px;color:var(--muted);
 margin-top:4px}.family-tag{display:inline-flex;align-items:center;gap:6px;font-size:10px;
 border:1px solid var(--line);border-radius:5px;padding:4px 7px;color:#526779}
.score-cell{font-family:var(--mono);font-weight:700}.mini-meter{height:4px;background:#eaf0f4;
 border-radius:4px;margin-top:6px;width:70px}.mini-meter i{display:block;height:100%;background:#248b94;border-radius:4px}
.state{font-size:10px;display:inline-block;border-radius:5px;padding:4px 7px;background:#f0f3f6;color:#617384}
.state.SUPPORTED{background:#fff0eb;color:#a75638}.state.WEAKENED{background:#eaf6f2;color:#267568}
.state.INCONCLUSIVE_ERROR{background:#fff6df;color:#876717}.state.REJECTED{background:#f9eefa;color:#805185}
.selection-note{font-size:11px;color:var(--muted);padding:12px 22px;border-top:1px solid var(--line);
 line-height:1.75;background:#fcfdfe}.journey{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));
 gap:16px;margin:22px 0}.journey-step{display:flex;gap:10px;font-size:11px;line-height:1.7;color:var(--muted)}
.step-number{background:#e6eff2;color:#317181;border-radius:6px;min-width:25px;height:25px;
 display:grid;place-items:center;font-family:var(--mono);font-size:11px}.journey-step b{display:block;color:#354f60;font-size:12px}
.filters{display:none;gap:12px;align-items:end;flex-wrap:wrap;padding:17px 23px;border-top:1px solid var(--line)}
.enhanced .filters{display:flex}.filters label{display:grid;gap:6px;font-size:11px;color:var(--muted)}
.filters label:first-child{flex:1;min-width:180px}.filters input,.filters select{height:39px;background:white;
 border:1px solid #d7e1e7;border-radius:6px;padding:0 12px;color:var(--ink);min-width:0;width:100%}
.filter-count{font-size:11px;color:var(--muted);padding:9px 0}.filter-empty{padding:40px;text-align:center;
 color:var(--muted)}.list-foot{margin-top:23px}.list-foot summary,.technical summary{cursor:pointer;font-size:12px;
 color:#527384;padding:13px 0;font-weight:600}.technical{margin-top:17px;border-top:1px solid var(--line)}
.back-link{display:inline-block;margin-bottom:20px;color:var(--muted);font-size:12px}
.detail-pager{display:flex;justify-content:space-between;gap:20px;margin-top:24px}
.finding{padding:28px;margin:0;border:1px solid var(--line);border-radius:11px;box-shadow:none}
.finding .fhead{padding-bottom:23px;border-bottom:1px solid var(--line);margin-bottom:24px}
.finding .rank{font-size:10px;letter-spacing:2px;color:var(--accent)}.finding .vtype{font-size:24px;margin:7px 0 10px}
.finding .prio{font-size:37px;letter-spacing:-1px}.finding .pcaption{font-family:var(--sans);font-size:11px}
.finding .meterwrap{max-width:260px}.finding .ep{font-size:12px;max-width:700px}
.detail-section{margin-top:27px}.detail-section h2{font-size:16px;margin:0 0 13px;display:flex;gap:10px;align-items:center}
.detail-section h2 span{color:var(--accent);font-family:var(--mono);font-size:11px;font-weight:500}
.plain-intro{font-size:14px;line-height:1.9;color:#4a6273;margin:0 0 15px}
.evidence-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
.evidence-item{border:1px solid #e3eaee;background:#fafcfd;border-radius:7px;padding:15px}
.evidence-item b{font-size:12px;display:block}.evidence-item p{font-size:12px;line-height:1.8;color:var(--muted);
 margin:7px 0}.evidence-meta{font-family:var(--mono);font-size:10px;overflow-wrap:anywhere;color:#687c8c}
.missing-note{padding:17px 20px;background:#f4f7f9;border-radius:7px;font-size:12px;color:#617483;line-height:1.8}
.payload-card{border:1px solid var(--line);border-radius:8px;margin:12px 0;overflow:hidden}
.payload-head{background:#f8fafc;padding:13px 17px;display:flex;justify-content:space-between;gap:12px;align-items:center}
.payload-head b{font-size:12px}.payload-body{padding:17px}.payload-values{display:grid;grid-template-columns:1fr 1fr;gap:13px}
.payload-values label{font-size:10px;color:var(--muted);display:block;margin-bottom:6px}
.payload-values pre{margin:0;font-size:12px;padding:12px;background:#132f40;color:#d5eee9;
 border-radius:6px;white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.7}
.payload-body p{font-size:12px;line-height:1.8;color:#526b7c}.payload-body ul{font-size:12px;line-height:1.8;color:#526b7c;padding-left:19px}
.payload-meta{font-size:10px;color:var(--muted);line-height:1.9;overflow-wrap:anywhere}
.delta-table{width:100%;border-collapse:collapse;font-size:11px}.delta-table th,.delta-table td{
 text-align:left;padding:8px;border-bottom:1px solid #edf1f4;overflow-wrap:anywhere}
.delta-table th{color:var(--muted);font-weight:500}.vpanel{padding:20px;background:#f2f8f9;border:1px solid #daebed;border-radius:8px}
.vpanel .vscore{font-size:15px}.vbadge{display:inline-block;border-radius:5px;font-size:11px;
 padding:4px 9px;color:white}.vbadge.high{background:#a85740}.vbadge.low{background:#287867}
.vbadge.muted{background:#627788}.vhead{display:flex;flex-wrap:wrap;gap:16px;align-items:center;margin-bottom:9px}
.fix{padding:23px;background:#f0f8f5;border:1px solid #d9ebe2;border-radius:8px;margin-top:14px}
.fixhead{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.fixchip{font-size:10px;color:#2b7764;
 border:1px solid #c5e1d5;padding:3px 7px;border-radius:4px}.fixlead{font-size:13px;line-height:1.8;margin:12px 0}
.fixgrid{display:grid;grid-template-columns:1fr 1fr;gap:25px}.fixsub{font-size:12px;font-weight:700;
 color:#267360}.fix ul{padding-left:17px;font-size:12px;line-height:1.9;color:#4c6e62}
.fixnote,.fixdisc{font-size:11px;line-height:1.9;color:#537867}.fixdisc{display:block;margin-top:14px}
.ids{overflow-wrap:anywhere;margin-top:24px;font-size:10px;line-height:1.9}
.ko-en{font-size:10px;margin-left:8px;color:var(--muted);font-weight:400;letter-spacing:.3px}
.reading-guide{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:22px}
.reading-guide .panel-body{font-size:13px;line-height:1.9;color:#567080}
.method-chart .chart-grid{margin-top:18px}.notice{box-shadow:none}.notice.small{font-style:normal}
.rec{display:block;overflow-x:auto}.rec td,.rec th{min-width:85px}.why .lab{font-size:12px;color:#506b7b}
footer{display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;font-size:10px;margin-top:27px;
 color:#778b98;border-color:#dfe8ed}footer .warn{color:#778b98}
@media(min-width:1500px){.main-content{padding-inline:46px}.map-canvas{min-height:283px}.endpoint-node{padding:14px}}
@media(max-width:1150px){.sidebar{width:190px;padding-inline:14px}.workspace{margin-left:190px}
 .main-content{padding:27px 24px}.topbar{padding-inline:24px}.overview-grid{grid-template-columns:minmax(0,1.9fr) minmax(220px,1fr)}
 .map-canvas{padding:17px;gap:20px}.map-root{flex-basis:70px}.map-root:after{right:-20px;width:23px}
 .map-branches{gap:9px;padding-left:14px}.endpoint-node:before{left:-15px;width:14px}.metric{padding:18px 16px}
 .candidate-table td,.candidate-table th{padding-inline:12px}.map-branches{grid-template-columns:1fr}}
@media(max-width:850px){.sidebar{position:static;width:100%;padding:17px 22px;display:block}.sidebar small,
 .nav-label,.sidebar-bottom{display:none}.sidebar nav{display:flex;gap:7px;margin-top:13px}.sidebar nav a{margin:0;padding:9px 12px}
 .workspace{margin-left:0}.topbar{height:58px}.overview-grid{grid-template-columns:1fr 1fr}.map-branches{grid-template-columns:1fr}
 .map-canvas{gap:22px}.metrics{gap:10px}.metric-label{font-size:11px}.metric-note{font-size:10px}.page-heading{align-items:flex-start}
 .journey{grid-template-columns:1fr 1fr}}
@media(max-width:650px){.main-content{padding:24px 16px}.topbar{padding-inline:17px}.crumb{font-size:10px}
 .snapshot-badge{display:none}.metrics{grid-template-columns:1fr 1fr}.overview-grid,.reading-guide{grid-template-columns:1fr}
 .map-branches{grid-template-columns:1fr 1fr}.map-canvas{gap:22px;padding:18px 12px}.map-root{flex-basis:62px}
 .map-root strong{font-size:10px}.endpoint-node{padding:8px}.candidate-node .node-name{max-width:70px}
 .page-heading{display:block}.page-heading>.button{margin-top:16px}h1.page-title{font-size:25px}
 .target-chip{font-size:10px}.family-panel .donut-layout{flex-direction:row}.panel-head{padding:18px}
 .panel-body{padding-inline:18px}.finding{padding:20px 17px}.evidence-grid,.payload-values,.fixgrid{grid-template-columns:1fr}
 .finding .meterwrap{width:100%;max-width:none;text-align:left}.finding .prio{font-size:32px}
 .fix{padding:17px}.journey{gap:15px}.sidebar nav a{font-size:12px;padding-inline:10px}.nav-icon{font-size:16px}
 .filters{padding-inline:17px}.filters label{flex:1;min-width:125px}.filters label:first-child{flex-basis:100%}
 .sidebar nav{display:grid;grid-template-columns:1fr 1fr 1.2fr;gap:4px}
 .sidebar nav a{font-size:11px;white-space:nowrap;gap:6px;justify-content:center;padding-inline:6px}}
@media(max-width:390px){.map-branches{grid-template-columns:1fr}.sidebar nav a{padding-inline:7px}}
@media(prefers-reduced-motion:no-preference){.button,.candidate-node{transition:background .15s}}
@media print{.sidebar,.topbar,.filters,.back-link,.detail-pager,.skip-link,.page-heading>.button{display:none!important}
 .workspace{margin:0}.main-content{padding:0}.panel,.finding,.metric{box-shadow:none;break-inside:avoid}
 .table-scroll,.rec{overflow:visible}body{background:white}.overview-grid{grid-template-columns:2fr 1fr}
 .metrics{grid-template-columns:repeat(4,1fr)}.report-page{break-after:page}.technical[open]{break-inside:auto}}
"""

# No report data is interpolated into JavaScript; all data comes from escaped DOM.
SCRIPT = """(() => {
  'use strict';
  const pages = Array.from(document.querySelectorAll('.report-page'));
  const nav = Array.from(document.querySelectorAll('.sidebar nav a'));
  function route(focus) {
    const id = location.hash.slice(1);
    const page = pages.find(p => p.id === id) || document.getElementById('overview');
    pages.forEach(p => p.classList.toggle('active', p === page));
    nav.forEach(a => {
      const current = a.hash === '#' + page.id ||
        (page.id.startsWith('candidate-') && a.hash === '#candidates');
      if (current) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    });
    const heading = page.querySelector('h1');
    document.querySelector('.skip-link').setAttribute('href', '#' + page.id);
    document.title = (heading ? heading.textContent : '분석 개요') + ' · VulnSpider';
    document.getElementById('current-page').textContent = heading ? heading.textContent : '분석 개요';
    if (focus && heading) { heading.focus({preventScroll:true}); window.scrollTo(0, 0); }
  }
  route(false);
  document.body.classList.add('enhanced');
  window.addEventListener('hashchange', () => route(true));
  document.querySelector('.skip-link').addEventListener('click', event => {
    event.preventDefault();
    const heading = document.querySelector('.report-page.active h1');
    if (heading) heading.focus();
  });
  document.querySelector('[data-print]').addEventListener('click', () => window.print());
  const search = document.getElementById('candidate-search');
  const family = document.getElementById('family-filter');
  const state = document.getElementById('state-filter');
  const rows = Array.from(document.querySelectorAll('#candidate-list tbody tr'));
  function filter() {
    const query = search.value.trim().toLocaleLowerCase();
    let count = 0;
    rows.forEach(row => {
      const match = row.textContent.toLocaleLowerCase().includes(query) &&
        (!family.value || row.dataset.family === family.value) &&
        (!state.value || row.dataset.state === state.value);
      row.hidden = !match;
      if (match) count++;
    });
    document.getElementById('filter-count').textContent = count + ' / ' + rows.length + '개 표시';
    document.getElementById('filter-empty').hidden = count !== 0;
  }
  search.addEventListener('input', filter);
  family.addEventListener('change', filter);
  state.addEventListener('change', filter);
  document.getElementById('reset-filters').addEventListener('click', () => {
    search.value = ''; family.value = ''; state.value = ''; filter(); search.focus();
  });
  filter();
})();"""

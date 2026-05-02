"""보고서 생성 모듈 — HTML / JSON / 텍스트 형식으로 취약점 보고서를 출력합니다."""
import json
import os
from datetime import datetime


SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}

SEVERITY_KO = {
    'critical': '심각',
    'high': '높음',
    'medium': '중간',
    'low': '낮음',
    'info': '정보',
}

CATEGORY_KO = {
    'server':   '서버 상태',
    'network':  '네트워크',
    'process':  '프로세스',
    'log':      '로그',
    'attack':   '공격 탐지',
    'port':     '포트 스캔',
    'pii':      '개인정보',
}

SEV_COLOR = {
    'critical': ('#dc2626', '#fef2f2', '🔴'),
    'high':     ('#ea580c', '#fff7ed', '🟠'),
    'medium':   ('#d97706', '#fffbeb', '🟡'),
    'low':      ('#2563eb', '#eff6ff', '🔵'),
    'info':     ('#6b7280', '#f9fafb', '⚪'),
}


def _sort_findings(findings: list) -> list:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get('severity', 'info'), 9))


def _count_by_severity(findings: list) -> dict:
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in findings:
        s = f.get('severity', 'info')
        counts[s] = counts.get(s, 0) + 1
    return counts


def generate(findings: list, fmt: str, output_base: str) -> str:
    sorted_findings = _sort_findings(findings)
    counts = _count_by_severity(findings)

    if fmt == 'json':
        return _write_json(sorted_findings, counts, output_base)
    elif fmt == 'text':
        return _write_text(sorted_findings, counts, output_base)
    else:
        return _write_html(sorted_findings, counts, output_base)


# ── JSON ─────────────────────────────────────────────────────────────────────

def _write_json(findings, counts, base) -> str:
    path = f'{base}.json'
    data = {
        'scan_time': datetime.now().isoformat(),
        'summary': counts,
        'total': len(findings),
        'findings': findings,
    }
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return os.path.abspath(path)


# ── TEXT ─────────────────────────────────────────────────────────────────────

def _write_text(findings, counts, base) -> str:
    path = f'{base}.txt'
    lines = [
        '=' * 70,
        '  보안 취약점 탐지 보고서',
        f'  생성 시각: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
        '=' * 70,
        '',
        f'[요약] 심각:{counts["critical"]}  높음:{counts["high"]}  '
        f'중간:{counts["medium"]}  낮음:{counts["low"]}  정보:{counts["info"]}',
        '',
    ]
    for f in findings:
        sev = f.get('severity', 'info').upper()
        lines += [
            '-' * 70,
            f'[{sev}] {f["id"]} — {f["title"]}',
            f'설명: {f["description"]}',
            f'권고: {f["recommendation"]}',
        ]
        if f.get('details'):
            lines.append('상세:')
            details = f['details']
            if isinstance(details, dict):
                for k, v in details.items():
                    lines.append(f'  {k}: {v}')
            elif isinstance(details, list):
                for item in details[:5]:
                    lines.append(f'  - {item}')
        lines.append('')
    with open(path, 'w', encoding='utf-8') as fp:
        fp.write('\n'.join(lines))
    return os.path.abspath(path)


# ── HTML ─────────────────────────────────────────────────────────────────────

def _details_html(details) -> str:
    if not details:
        return ''
    rows = []
    if isinstance(details, dict):
        for k, v in details.items():
            if isinstance(v, (list, dict)):
                v_str = json.dumps(v, ensure_ascii=False, indent=2)
                rows.append(f'<tr><td class="dk">{k}</td><td><pre class="pre-wrap">{_esc(v_str)}</pre></td></tr>')
            else:
                rows.append(f'<tr><td class="dk">{k}</td><td>{_esc(str(v))}</td></tr>')
    elif isinstance(details, list):
        for i, item in enumerate(details[:20], 1):
            item_str = json.dumps(item, ensure_ascii=False) if isinstance(item, dict) else str(item)
            rows.append(f'<tr><td class="dk">{i}</td><td><pre class="pre-wrap">{_esc(item_str)}</pre></td></tr>')
    if not rows:
        return ''
    return '<table class="dtable">' + ''.join(rows) + '</table>'


def _esc(s: str) -> str:
    return (s.replace('&', '&amp;').replace('<', '&lt;')
             .replace('>', '&gt;').replace('"', '&quot;'))


def _write_html(findings, counts, base) -> str:
    path = f'{base}.html'
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # 카테고리별 집계
    cat_counts: dict[str, dict] = {}
    for f in findings:
        cat = f.get('category', 'other')
        sev = f.get('severity', 'info')
        cat_counts.setdefault(cat, {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0})
        cat_counts[cat][sev] += 1

    # 심각/높음 항목만 추출 (빠른 확인용)
    urgent = [f for f in findings if f.get('severity') in ('critical', 'high')]

    cards_html = ''
    for f in findings:
        sev = f.get('severity', 'info')
        color, bg, icon = SEV_COLOR.get(sev, ('#6b7280', '#f9fafb', '⚪'))
        sev_ko = SEVERITY_KO.get(sev, sev)
        cat_ko = CATEGORY_KO.get(f.get('category', ''), f.get('category', ''))
        det_html = _details_html(f.get('details'))

        cards_html += f'''
        <div class="card" id="{f["id"]}">
          <div class="card-header" style="background:{bg};border-left:4px solid {color}">
            <div class="card-title">
              <span class="badge" style="background:{color}">{icon} {sev_ko}</span>
              <span class="fid">{f["id"]}</span>
              <span class="cat-badge">{cat_ko}</span>
              <strong>{_esc(f["title"])}</strong>
            </div>
            <button class="toggle-btn" onclick="toggle(this)">▼ 상세</button>
          </div>
          <div class="card-body collapsed">
            <p class="desc">{_esc(f["description"])}</p>
            {det_html}
            <div class="rec">
              <span class="rec-icon">💡</span>
              <strong>개선 방향:</strong> {_esc(f["recommendation"])}
            </div>
            <p class="ts">탐지 시각: {f.get("timestamp","")}</p>
          </div>
        </div>'''

    # 긴급 목록
    urgent_rows = ''.join(
        f'<tr onclick="document.getElementById(\'{f["id"]}\').scrollIntoView({{behavior:\'smooth\'}})" style="cursor:pointer">'
        f'<td><span style="color:{SEV_COLOR[f["severity"]][0]};font-weight:700">{SEVERITY_KO[f["severity"]]}</span></td>'
        f'<td>{f["id"]}</td>'
        f'<td>{CATEGORY_KO.get(f["category"], f["category"])}</td>'
        f'<td>{_esc(f["title"])}</td></tr>'
        for f in urgent
    ) or '<tr><td colspan="4" style="text-align:center;color:#16a34a">긴급 항목 없음</td></tr>'

    html = f'''<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>보안 취약점 탐지 보고서 — {now}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:"Malgun Gothic",system-ui,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}}
.header{{background:linear-gradient(135deg,#1e293b,#0f172a);padding:2rem;border-bottom:1px solid #334155}}
.header h1{{font-size:1.6rem;color:#f1f5f9;margin-bottom:.4rem}}
.header p{{color:#94a3b8;font-size:.9rem}}
.container{{max-width:1200px;margin:0 auto;padding:2rem 1rem}}
.summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:1rem;margin-bottom:2rem}}
.stat-card{{background:#1e293b;border-radius:12px;padding:1.2rem;text-align:center;border:1px solid #334155}}
.stat-num{{font-size:2.2rem;font-weight:700;margin-bottom:.3rem}}
.stat-label{{font-size:.8rem;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em}}
.c-critical{{color:#ef4444}}.c-high{{color:#f97316}}.c-medium{{color:#f59e0b}}
.c-low{{color:#60a5fa}}.c-info{{color:#94a3b8}}
.section-title{{font-size:1.1rem;font-weight:600;color:#f1f5f9;margin:1.5rem 0 .8rem;padding-bottom:.4rem;border-bottom:1px solid #334155}}
.urgent-table{{width:100%;border-collapse:collapse;background:#1e293b;border-radius:10px;overflow:hidden;margin-bottom:2rem}}
.urgent-table th{{background:#0f172a;color:#94a3b8;font-size:.8rem;padding:.7rem 1rem;text-align:left;text-transform:uppercase;letter-spacing:.05em}}
.urgent-table td{{padding:.7rem 1rem;border-top:1px solid #334155;font-size:.9rem}}
.urgent-table tr:hover td{{background:#334155}}
.card{{background:#1e293b;border-radius:10px;margin-bottom:1rem;overflow:hidden;border:1px solid #334155}}
.card-header{{padding:1rem 1.2rem;display:flex;justify-content:space-between;align-items:center;gap:.8rem}}
.card-title{{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap;flex:1}}
.badge{{padding:.25rem .6rem;border-radius:6px;font-size:.75rem;font-weight:600;color:#fff;white-space:nowrap}}
.fid{{font-size:.75rem;color:#64748b;font-family:monospace;white-space:nowrap}}
.cat-badge{{font-size:.75rem;background:#334155;color:#94a3b8;padding:.2rem .5rem;border-radius:4px}}
.card-header strong{{color:#f1f5f9;font-size:.95rem}}
.toggle-btn{{background:none;border:1px solid #475569;color:#94a3b8;padding:.3rem .7rem;border-radius:6px;cursor:pointer;white-space:nowrap;font-size:.8rem}}
.toggle-btn:hover{{background:#334155}}
.card-body{{padding:0 1.2rem;overflow:hidden;max-height:0;transition:max-height .3s ease,padding .3s ease}}
.card-body.open{{padding:1rem 1.2rem;max-height:none}}
.card-body.collapsed{{padding:0 1.2rem;max-height:0}}
.desc{{color:#cbd5e1;margin-bottom:.8rem;line-height:1.6;font-size:.9rem}}
.dtable{{width:100%;border-collapse:collapse;margin:.5rem 0 1rem;font-size:.85rem}}
.dtable td{{padding:.5rem .7rem;border:1px solid #334155;vertical-align:top}}
.dtable td.dk{{background:#0f172a;color:#94a3b8;font-weight:500;width:30%;white-space:nowrap}}
.pre-wrap{{white-space:pre-wrap;word-break:break-all;max-height:200px;overflow-y:auto;background:#0f172a;padding:.4rem;border-radius:4px;font-size:.8rem;color:#86efac}}
.rec{{background:#0f172a;border-left:3px solid #3b82f6;padding:.7rem 1rem;border-radius:0 6px 6px 0;font-size:.88rem;margin-top:.5rem;line-height:1.6}}
.rec-icon{{margin-right:.3rem}}
.ts{{font-size:.75rem;color:#475569;margin-top:.7rem;text-align:right}}
.filter-bar{{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1rem}}
.filter-btn{{padding:.4rem .9rem;border-radius:20px;border:1px solid #475569;background:transparent;color:#94a3b8;cursor:pointer;font-size:.82rem}}
.filter-btn.active,.filter-btn:hover{{background:#3b82f6;border-color:#3b82f6;color:#fff}}
.footer{{text-align:center;padding:2rem;color:#475569;font-size:.8rem;border-top:1px solid #1e293b;margin-top:2rem}}
</style>
</head>
<body>
<div class="header">
  <div class="container" style="padding:0">
    <h1>🛡️ 보안 취약점 탐지 보고서</h1>
    <p>생성 시각: {now} &nbsp;|&nbsp; 총 {len(findings)}개 항목 탐지</p>
  </div>
</div>
<div class="container">

  <!-- 요약 카드 -->
  <div class="summary-grid">
    <div class="stat-card">
      <div class="stat-num c-critical">{counts["critical"]}</div>
      <div class="stat-label">심각 (Critical)</div>
    </div>
    <div class="stat-card">
      <div class="stat-num c-high">{counts["high"]}</div>
      <div class="stat-label">높음 (High)</div>
    </div>
    <div class="stat-card">
      <div class="stat-num c-medium">{counts["medium"]}</div>
      <div class="stat-label">중간 (Medium)</div>
    </div>
    <div class="stat-card">
      <div class="stat-num c-low">{counts["low"]}</div>
      <div class="stat-label">낮음 (Low)</div>
    </div>
    <div class="stat-card">
      <div class="stat-num c-info">{counts["info"]}</div>
      <div class="stat-label">정보 (Info)</div>
    </div>
    <div class="stat-card">
      <div class="stat-num" style="color:#f1f5f9">{len(findings)}</div>
      <div class="stat-label">전체</div>
    </div>
  </div>

  <!-- 긴급 항목 -->
  <div class="section-title">⚠️ 즉시 조치 필요 항목 ({len(urgent)}개)</div>
  <table class="urgent-table">
    <thead><tr><th>심각도</th><th>ID</th><th>카테고리</th><th>항목</th></tr></thead>
    <tbody>{urgent_rows}</tbody>
  </table>

  <!-- 전체 결과 -->
  <div class="section-title">📋 전체 탐지 결과</div>
  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterSev('all',this)">전체</button>
    <button class="filter-btn" onclick="filterSev('critical',this)">🔴 심각</button>
    <button class="filter-btn" onclick="filterSev('high',this)">🟠 높음</button>
    <button class="filter-btn" onclick="filterSev('medium',this)">🟡 중간</button>
    <button class="filter-btn" onclick="filterSev('low',this)">🔵 낮음</button>
    <button class="filter-btn" onclick="filterSev('info',this)">⚪ 정보</button>
  </div>

  <div id="findings">
{cards_html}
  </div>

</div>
<div class="footer">
  보안 취약점 탐지 시스템 v1.0 &nbsp;|&nbsp; {now} &nbsp;|&nbsp;
  이 보고서는 내부 보안 감사 목적으로만 사용하십시오.
</div>

<script>
function toggle(btn) {{
  var body = btn.closest('.card').querySelector('.card-body');
  var open = body.classList.contains('open');
  body.classList.toggle('open', !open);
  body.classList.toggle('collapsed', open);
  btn.textContent = open ? '▼ 상세' : '▲ 닫기';
}}

function filterSev(sev, btn) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.card').forEach(card => {{
    if (sev === 'all') {{
      card.style.display = '';
    }} else {{
      var badge = card.querySelector('.badge');
      var sevMap = {{'심각':'critical','높음':'high','중간':'medium','낮음':'low','정보':'info'}};
      var cardSev = '';
      for (var k in sevMap) {{ if (badge && badge.textContent.includes(k)) cardSev = sevMap[k]; }}
      card.style.display = (cardSev === sev) ? '' : 'none';
    }}
  }});
}}

// 기본으로 모든 카드 접기
document.querySelectorAll('.card-body').forEach(b => {{
  b.classList.add('collapsed');
  b.classList.remove('open');
}});
</script>
</body>
</html>'''

    with open(path, 'w', encoding='utf-8') as f:
        f.write(html)
    return os.path.abspath(path)

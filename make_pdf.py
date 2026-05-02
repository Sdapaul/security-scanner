"""사용법.md → 사용법.pdf 변환 (reportlab, 맑은 고딕)"""
import re
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, Preformatted
)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# ── 한글 폰트 등록 ──────────────────────────────────────────
pdfmetrics.registerFont(TTFont('Malgun',   'C:/Windows/Fonts/malgun.ttf'))
pdfmetrics.registerFont(TTFont('MalgunBd', 'C:/Windows/Fonts/malgunbd.ttf'))
pdfmetrics.registerFontFamily('Malgun', normal='Malgun', bold='MalgunBd')

W, H = A4
MARGIN = 20 * mm

# ── 색상 ────────────────────────────────────────────────────
C_BG     = colors.HexColor('#0b1220')
C_CARD   = colors.HexColor('#131f33')
C_BORDER = colors.HexColor('#1e3050')
C_ACCENT = colors.HexColor('#3b82f6')
C_TEXT   = colors.HexColor('#dde6f0')
C_MUTED  = colors.HexColor('#6b82a0')
C_GREEN  = colors.HexColor('#22c55e')
C_ORANGE = colors.HexColor('#f97316')
C_RED    = colors.HexColor('#ef4444')
C_YELLOW = colors.HexColor('#eab308')
C_CODE   = colors.HexColor('#070d18')
C_CODE_T = colors.HexColor('#4ade80')
C_WHITE  = colors.white

# ── 스타일 ──────────────────────────────────────────────────
def make_styles():
    K = dict(fontName='Malgun', textColor=C_TEXT)
    return {
        'h1': ParagraphStyle('h1', fontSize=20, fontName='MalgunBd',
                             textColor=C_WHITE, leading=28, spaceAfter=6),
        'h2': ParagraphStyle('h2', fontSize=14, fontName='MalgunBd',
                             textColor=C_ACCENT, leading=20, spaceBefore=14, spaceAfter=4),
        'h3': ParagraphStyle('h3', fontSize=11, fontName='MalgunBd',
                             textColor=C_GREEN, leading=16, spaceBefore=8, spaceAfter=3),
        'body':   ParagraphStyle('body',   fontSize=9,   leading=15, **K),
        'bullet': ParagraphStyle('bullet', fontSize=9,   leading=15,
                                 leftIndent=12, bulletIndent=2, **K),
        'note':   ParagraphStyle('note',   fontSize=8.5, leading=13,
                                 leftIndent=8,  textColor=C_MUTED, fontName='Malgun'),
        'code':   ParagraphStyle('code',   fontSize=8,   leading=12,
                                 fontName='Courier', textColor=C_CODE_T,
                                 backColor=C_CODE, leftIndent=8, rightIndent=8),
        'th': ParagraphStyle('th', fontSize=8.5, fontName='MalgunBd',
                             textColor=C_WHITE, leading=12, alignment=1),
        'td': ParagraphStyle('td', fontSize=8.5, fontName='Malgun',
                             textColor=C_TEXT,  leading=12),
    }

ST = make_styles()

TABLE_STYLE = TableStyle([
    ('BACKGROUND',   (0, 0), (-1, 0),  C_CARD),
    ('TEXTCOLOR',    (0, 0), (-1, 0),  C_WHITE),
    ('FONTNAME',     (0, 0), (-1, 0),  'MalgunBd'),
    ('FONTSIZE',     (0, 0), (-1, -1), 8.5),
    ('FONTNAME',     (0, 1), (-1, -1), 'Malgun'),
    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#131f33'), colors.HexColor('#0f1a2e')]),
    ('TEXTCOLOR',    (0, 1), (-1, -1), C_TEXT),
    ('GRID',         (0, 0), (-1, -1), 0.4, C_BORDER),
    ('VALIGN',       (0, 0), (-1, -1), 'MIDDLE'),
    ('LEFTPADDING',  (0, 0), (-1, -1), 6),
    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ('TOPPADDING',   (0, 0), (-1, -1), 4),
    ('BOTTOMPADDING',(0, 0), (-1, -1), 4),
])

# ── MD 파싱 → Flowables ──────────────────────────────────────
def parse_md(text: str) -> list:
    lines  = text.splitlines()
    story  = []
    i      = 0
    usable = W - 2 * MARGIN

    def p(s, st=ST['body']): return Paragraph(s.replace('&','&amp;').replace('<','&lt;'), st)
    def sp(h=4): return Spacer(1, h)
    def hr(): return HRFlowable(width='100%', thickness=0.5, color=C_BORDER, spaceAfter=6)

    in_code  = False
    code_buf = []
    in_table = False
    tbl_rows = []

    while i < len(lines):
        line = lines[i]

        # ── 코드 블록 ──
        if line.startswith('```'):
            if not in_code:
                in_code = True
                code_buf = []
            else:
                in_code = False
                code_text = '\n'.join(code_buf)
                story.append(Preformatted(code_text, ST['code'],
                                          maxLineLength=90))
                story.append(sp(4))
            i += 1
            continue

        if in_code:
            code_buf.append(line)
            i += 1
            continue

        # ── 표 ──
        if line.startswith('|'):
            cells = [c.strip() for c in line.strip('|').split('|')]
            if not in_table:
                in_table = True
                tbl_rows = [cells]
            else:
                # 구분선(---|---) 무시
                if all(re.match(r'^[-: ]+$', c) for c in cells):
                    i += 1
                    continue
                tbl_rows.append(cells)
            i += 1
            continue
        elif in_table:
            in_table = False
            if tbl_rows:
                col_n  = len(tbl_rows[0])
                col_w  = usable / col_n
                data   = []
                for ri, row in enumerate(tbl_rows):
                    st = ST['th'] if ri == 0 else ST['td']
                    data.append([Paragraph(c.replace('&','&amp;').replace('<','&lt;'), st)
                                 for c in row])
                tbl = Table(data, colWidths=[col_w] * col_n, repeatRows=1)
                tbl.setStyle(TABLE_STYLE)
                story.append(tbl)
                story.append(sp(6))
            tbl_rows = []

        stripped = line.strip()

        # 빈 줄
        if not stripped:
            story.append(sp(4))
            i += 1
            continue

        # 제목
        if stripped.startswith('# ') and not stripped.startswith('## '):
            story.append(sp(4))
            story.append(p(stripped[2:], ST['h1']))
            story.append(hr())
            story.append(sp(2))
        elif stripped.startswith('## '):
            story.append(sp(6))
            story.append(p(stripped[3:], ST['h2']))
            story.append(HRFlowable(width='100%', thickness=0.3,
                                    color=C_BORDER, spaceAfter=3))
        elif stripped.startswith('### '):
            story.append(p(stripped[4:], ST['h3']))
        # 수평선
        elif stripped.startswith('---'):
            story.append(hr())
        # 인용(주의 메모)
        elif stripped.startswith('> '):
            story.append(p(stripped[2:], ST['note']))
        # 순서없는 목록
        elif re.match(r'^[-*] ', stripped):
            txt = re.sub(r'^[-*] ', '', stripped)
            txt = re.sub(r'`([^`]+)`', r'<font name="Courier" color="#4ade80">\1</font>', txt)
            story.append(Paragraph(f'• {txt}', ST['bullet']))
        # 순서있는 목록
        elif re.match(r'^\d+\. ', stripped):
            txt = re.sub(r'^\d+\. ', '', stripped)
            story.append(Paragraph(f'  {txt}', ST['bullet']))
        # 인라인 코드 포함 일반 텍스트
        else:
            txt = stripped
            txt = re.sub(r'`([^`]+)`',
                         r'<font name="Courier" color="#4ade80">\1</font>', txt)
            txt = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', txt)
            story.append(p(txt))

        i += 1

    # 미처리 테이블
    if in_table and tbl_rows:
        col_n = len(tbl_rows[0])
        col_w = usable / col_n
        data  = []
        for ri, row in enumerate(tbl_rows):
            st = ST['th'] if ri == 0 else ST['td']
            data.append([Paragraph(c.replace('&','&amp;').replace('<','&lt;'), st)
                         for c in row])
        tbl = Table(data, colWidths=[col_w] * col_n, repeatRows=1)
        tbl.setStyle(TABLE_STYLE)
        story.append(tbl)

    return story


def on_page(canvas, doc):
    canvas.saveState()
    # 배경
    canvas.setFillColor(C_BG)
    canvas.rect(0, 0, W, H, fill=1, stroke=0)
    # 하단 페이지 번호
    canvas.setFont('Malgun', 8)
    canvas.setFillColor(C_MUTED)
    canvas.drawCentredString(W / 2, 12 * mm, f'{doc.page}')
    canvas.restoreState()


def build(md_path: str, pdf_path: str):
    with open(md_path, encoding='utf-8') as f:
        text = f.read()

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN,  bottomMargin=18 * mm,
        title='보안 스캐너 사용법',
        author='Security Scanner',
    )
    story = parse_md(text)
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    print(f'PDF 생성 완료: {pdf_path}')


if __name__ == '__main__':
    import os
    base = os.path.dirname(os.path.abspath(__file__))
    build(
        os.path.join(base, '사용법.md'),
        os.path.join(base, '사용법.pdf'),
    )

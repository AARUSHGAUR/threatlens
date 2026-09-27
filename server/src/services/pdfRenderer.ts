/**
 * PDF report renderer (PDFKit).
 *
 * SECURITY: the indicator is user-supplied and is rendered into a PDF, so every
 * dynamic string is sanitised before it reaches the document - control
 * characters are stripped, and text is never interpreted as PostScript or as a
 * file path. PDFKit writes text via its content stream; because we always emit
 * `doc.text()` with plain strings (no operators, no attachments, no external
 * references) the document cannot execute anything.
 */
import PDFDocument from 'pdfkit';
import { reportToMarkdown, type InvestigationReport } from './reportBuilder.js';

const PAGE_MARGIN = 46;
const INK = '#111827';
const MUTED = '#4b5563';
const LINE = '#d1d5db';
const ACCENT = '#1f2937';
const RISK_COLOURS: Record<string, string> = {
  CRITICAL: '#b91c1c',
  HIGH: '#c2410c',
  MEDIUM: '#a16207',
  LOW: '#0f766e',
  CLEAN: '#15803d',
};

/** Remove characters that would corrupt a PDF text stream. */
const clean = (value: unknown): string =>
  String(value ?? '')
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
    .replace(/\r\n?/g, '\n');

const truncate = (value: string, max = 180): string => (value.length <= max ? value : `${value.slice(0, max - 1)}…`);

export function renderReportPdf(report: InvestigationReport): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: 'A4',
      margins: { top: PAGE_MARGIN + 22, bottom: PAGE_MARGIN, left: PAGE_MARGIN, right: PAGE_MARGIN },
      info: {
        Title: clean(report.title),
        Author: 'ThreatLens CTI Platform',
        Subject: clean(report.indicator.value),
        Creator: 'ThreatLens 1.0.0',
      },
      autoFirstPage: true,
    });

    const chunks: Buffer[] = [];
    doc.on('data', (chunk: Buffer) => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', (err: Error) => reject(err));

    const pageWidth = doc.page.width - PAGE_MARGIN * 2;

    // ------------------------------------------------------------- helpers
    const bottomLimit = doc.page.height - PAGE_MARGIN;
    const heading = (text: string, level: 1 | 2 = 1): void => {
      if (level === 1) {
        // Only break the page when there is genuinely no room for a heading plus
        // a couple of lines of body text (avoids near-empty pages).
        if (doc.y > bottomLimit - 130) doc.addPage();
        doc.fillColor(ACCENT).font('Helvetica-Bold').fontSize(14).text(clean(text), { width: pageWidth });
        doc.moveDown(0.2);
        const y = doc.y;
        doc.moveTo(PAGE_MARGIN, y).lineTo(PAGE_MARGIN + pageWidth, y).lineWidth(0.7).strokeColor(LINE).stroke();
        doc.moveDown(0.5);
      } else {
        if (doc.y > bottomLimit - 80) doc.addPage();
        doc.moveDown(0.3);
        doc.fillColor(ACCENT).font('Helvetica-Bold').fontSize(11).text(clean(text), { width: pageWidth });
        doc.moveDown(0.2);
      }
    };

    const paragraph = (text: string, opts: { size?: number; color?: string; italic?: boolean; gap?: number } = {}): void => {
      doc.fillColor(opts.color ?? MUTED).font(opts.italic ? 'Helvetica-Oblique' : 'Helvetica').fontSize(opts.size ?? 9).text(clean(text), { width: pageWidth, align: 'left' });
      doc.moveDown(opts.gap ?? 0.4);
    };

    const bullet = (text: string, indent = 10): void => {
      doc.fillColor(MUTED).font('Helvetica').fontSize(9).text(`•  ${clean(text)}`, { width: pageWidth - indent, indent: 0 });
      doc.moveDown(0.15);
    };

    const keyValueTable = (rows: Array<[string, string]>): void => {
      const colWidth = pageWidth * 0.32;
      for (const [k, v] of rows) {
        const startY = doc.y;
        doc.font('Helvetica-Bold').fontSize(8.5).fillColor(ACCENT).text(clean(k), { width: colWidth - 6 });
        const valueText = clean(v) || '-';
        doc.font('Helvetica').fontSize(8.5).fillColor(MUTED).text(valueText, { width: pageWidth - colWidth - 4 });
        // Draw the value relative to the row start so wrapped values align.
        const endY = doc.y;
        doc.y = Math.max(endY, startY + 11);
        doc.moveDown(0.12);
      }
      doc.moveDown(0.3);
    };

    const table = (headers: string[], rows: string[][]): void => {
      const weights = headers.map((h) => Math.min(2.2, Math.max(0.7, h.length / 10)));
      const totalWeight = weights.reduce((a, b) => a + b, 0);
      const widths = weights.map((w) => (w / totalWeight) * pageWidth);

      const drawHeader = (): void => {
        const y = doc.y;
        doc.rect(PAGE_MARGIN, y, pageWidth, 16).fill('#f3f4f6');
        doc.font('Helvetica-Bold').fontSize(7.5).fillColor(ACCENT);
        let x = PAGE_MARGIN;
        headers.forEach((h, i) => {
          doc.text(clean(h).toUpperCase(), x + 3, y + 4.5, { width: widths[i] - 6, ellipsis: true });
          x += widths[i];
        });
        doc.y = y + 16;
      };

      drawHeader();
      for (const row of rows) {
        // Estimate height: wrapped lines per cell * line height.
        let lines = 1;
        row.forEach((cell, i) => {
          const text = clean(cell) || '-';
          const approxChars = Math.max(8, Math.floor(widths[i] / 4.2));
          const wrapped = Math.ceil(text.length / approxChars) || 1;
          lines = Math.max(lines, Math.min(6, wrapped));
        });
        const height = lines * 9 + 4;
        if (doc.y + height > doc.page.height - PAGE_MARGIN) {
          doc.addPage();
          drawHeader();
        }
        const y = doc.y;
        let x = PAGE_MARGIN;
        doc.font('Helvetica').fontSize(7.5).fillColor(MUTED);
        row.forEach((cell, i) => {
          doc.text(truncate(clean(cell) || '-', 400), x + 3, y + 3, { width: widths[i] - 6, ellipsis: true });
          x += widths[i];
        });
        doc.y = y + height;
        doc.moveTo(PAGE_MARGIN, doc.y).lineTo(PAGE_MARGIN + pageWidth, doc.y).lineWidth(0.4).strokeColor('#e5e7eb').stroke();
      }
      doc.moveDown(0.6);
    };

    // -------------------------------------------------------------- header
    doc.rect(0, 0, doc.page.width, 74).fill('#111827');
    doc.fillColor('#f9fafb').font('Helvetica-Bold').fontSize(17).text('ThreatLens', PAGE_MARGIN, 24);
    doc.font('Helvetica').fontSize(9).fillColor('#d1d5db').text('Cyber Threat Intelligence & IOC Investigation Platform', PAGE_MARGIN, 45);
    doc.font('Helvetica-Bold').fontSize(8).fillColor('#fca5a5').text(clean(report.classification.label), PAGE_MARGIN, 58, { width: pageWidth, align: 'right' });

    // ------------------------------------------------------------- summary
    heading('Executive Summary');
    const riskColour = RISK_COLOURS[report.riskScore.level] ?? INK;
    doc.roundedRect(PAGE_MARGIN, doc.y, pageWidth, 46, 4).fill('#f9fafb');
    const boxY = doc.y + 8;
    doc.font('Helvetica').fontSize(8).fillColor(MUTED);
    doc.text('RISK SCORE', PAGE_MARGIN + 12, boxY);
    doc.font('Helvetica-Bold').fontSize(18).fillColor(riskColour).text(`${report.riskScore.score}`, PAGE_MARGIN + 12, boxY + 12);
    const scoreW = doc.widthOfString(`${report.riskScore.score}`);
    doc.font('Helvetica').fontSize(8).fillColor(MUTED).text('/ 100', PAGE_MARGIN + 20 + scoreW, boxY + 20);
    doc.font('Helvetica-Bold').fontSize(10).fillColor(riskColour).text(clean(report.riskScore.level), PAGE_MARGIN + 92, boxY + 16);
    doc.font('Helvetica').fontSize(8).fillColor(MUTED).text('CONFIDENCE', PAGE_MARGIN + 200, boxY);
    doc.font('Helvetica-Bold').fontSize(14).fillColor(INK).text(`${report.riskScore.confidence}%`, PAGE_MARGIN + 200, boxY + 12);
    doc.font('Helvetica').fontSize(8).fillColor(MUTED).text('VERDICT', PAGE_MARGIN + 290, boxY);
    doc.font('Helvetica-Bold').fontSize(11).fillColor(INK).text(clean(report.executiveSummary.verdict.toUpperCase()), PAGE_MARGIN + 290, boxY + 13);
    doc.font('Helvetica').fontSize(8).fillColor(MUTED).text('TECHNIQUES', PAGE_MARGIN + 380, boxY);
    doc.font('Helvetica-Bold').fontSize(14).fillColor(INK).text(String(report.attack.techniques.length), PAGE_MARGIN + 380, boxY + 12);
    doc.y += 56;

    paragraph(report.executiveSummary.narrative, { size: 9.5, color: INK });
    for (const finding of report.executiveSummary.keyFindings) bullet(finding);

    // Provenance banner - crucial for demo-mode honesty.
    if (report.provenance.demoDataUsed) {
      doc.roundedRect(PAGE_MARGIN, doc.y, pageWidth, 30, 3).fill('#fef3c7');
      doc.fillColor('#92400e').font('Helvetica-Bold').fontSize(8).text(
        'DEMO DATA - this report contains SIMULATED intelligence from the ThreatLens demonstration dataset. It must not be used for operational decisions.',
        PAGE_MARGIN + 8, doc.y + 6, { width: pageWidth - 16 },
      );
      doc.y += 36;
    }

    heading('Report Metadata');
    keyValueTable([
      ['Report ID', report.reportId],
      ['Investigation reference', report.investigation.reference],
      ['Status', report.investigation.status],
      ['Intelligence mode', report.generator.mode === 'demo' ? 'DEMO MODE (simulated)' : 'LIVE INTELLIGENCE'],
      ['Opened at', report.investigation.openedAt],
      ['Completed at', report.investigation.completedAt ?? 'n/a'],
      ['Analyst', report.investigation.analyst ?? 'Unknown analyst'],
      ['Indicator', `${report.indicator.value} (${report.indicator.typeLabel})`],
      ['Data origin', report.provenance.dataOrigin],
    ]);

    for (const section of report.sections) {
      heading(section.title, 1);
      doc.font('Helvetica-Oblique').fontSize(7.5).fillColor('#6b7280').text(`Evidence class: ${section.classification}`);
      doc.moveDown(0.3);
      paragraph(section.body);
      if (section.table) {
        // Section 1 (IOC information) is nicer as key/value pairs.
        if (section.id === 'ioc-information') {
          keyValueTable(section.table.rows.map(([k, v]) => [k ?? '', v ?? '']));
        } else {
          table(section.table.headers, section.table.rows);
        }
      }
      if (section.bullets) for (const b of section.bullets) bullet(b);
    }

    // -------------------------------------------------------------- footer
    const range = doc.bufferedPageRange();
    for (let i = range.start; i < range.start + range.count; i += 1) {
      doc.switchToPage(i);
      const y = doc.page.height - 30;
      doc.moveTo(PAGE_MARGIN, y).lineTo(PAGE_MARGIN + pageWidth, y).lineWidth(0.5).strokeColor(LINE).stroke();
      doc.font('Helvetica').fontSize(7).fillColor('#6b7280');
      doc.text(
        `ThreatLens CTI report ${report.reportId} - ${report.classification.label} - generated ${report.generatedAt}`,
        PAGE_MARGIN, y + 6, { width: pageWidth * 0.75 },
      );
      doc.text(`Page ${i - range.start + 1} of ${range.count}`, PAGE_MARGIN + pageWidth * 0.75, y + 6, { width: pageWidth * 0.25, align: 'right' });
    }

    doc.end();
  });
}

export { reportToMarkdown };

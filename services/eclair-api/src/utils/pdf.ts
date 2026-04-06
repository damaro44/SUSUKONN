import PDFDocument from "pdfkit";
import type { ComplianceAuditItem, TrainingPlan } from "../types/domain.js";

export function buildCompliancePdfBuffer(
  audits: ComplianceAuditItem[],
  trainings: TrainingPlan[],
  generatedAt: string
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 40, size: "A4" });
    const chunks: Buffer[] = [];

    doc.on("data", chunk => chunks.push(Buffer.from(chunk)));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    doc.fontSize(18).text("Eclair Technology Assistance");
    doc.fontSize(13).text("Compliance & Digitalization Report", { underline: true });
    doc.moveDown(0.5);
    doc.fontSize(10).text(`Generated at: ${generatedAt}`);

    doc.moveDown(1);
    doc.font("Helvetica-Bold").fontSize(12).text("Compliance Audit Findings");
    doc.font("Helvetica");
    doc.moveDown(0.35);

    if (!audits.length) {
      doc.fontSize(10).text("No compliance audit findings available.");
    } else {
      for (const item of audits) {
        doc
          .fontSize(10)
          .text(`- [${item.severity}] ${item.standard} | Owner: ${item.owner} | Due: ${item.dueDate}`)
          .text(`  Finding: ${item.finding}`)
          .text(`  Status: ${item.status}`)
          .moveDown(0.4);
      }
    }

    doc.moveDown(0.8);
    doc.font("Helvetica-Bold").fontSize(12).text("Training & Change Management");
    doc.font("Helvetica");
    doc.moveDown(0.35);

    if (!trainings.length) {
      doc.fontSize(10).text("No training plans available.");
    } else {
      for (const item of trainings) {
        doc
          .fontSize(10)
          .text(`- ${item.program} (${item.mode}) | Target: ${item.targetCompletion}%`)
          .text(`  Audience: ${item.audience}`)
          .text(`  Objective: ${item.objective}`)
          .moveDown(0.4);
      }
    }

    doc.end();
  });
}

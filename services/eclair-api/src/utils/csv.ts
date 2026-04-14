import type { ComplianceAuditItem, TrainingPlan } from "../types/domain.js";

function escapeCsv(value: string | number): string {
  const raw = String(value);
  if (/[",\n]/.test(raw)) {
    return `"${raw.replaceAll('"', '""')}"`;
  }
  return raw;
}

export function buildComplianceCsv(
  audits: ComplianceAuditItem[],
  trainings: TrainingPlan[],
  generatedAt: string
): string {
  const auditRows = audits.map(item =>
    [
      "audit",
      item.id,
      item.standard,
      item.severity,
      item.finding,
      item.owner,
      item.dueDate,
      item.status,
      item.createdAt
    ]
      .map(escapeCsv)
      .join(",")
  );

  const trainingRows = trainings.map(item =>
    [
      "training",
      item.id,
      item.program,
      item.mode,
      item.audience,
      item.targetCompletion,
      item.objective,
      item.createdAt
    ]
      .map(escapeCsv)
      .join(",")
  );

  const header = [
    "record_type",
    "id",
    "title_or_standard",
    "severity_or_mode",
    "description_or_finding",
    "owner_or_audience",
    "due_or_target",
    "status_or_objective",
    "created_at"
  ].join(",");

  return [
    `# Eclair Compliance Export generated at ${generatedAt}`,
    header,
    ...auditRows,
    ...trainingRows
  ].join("\n");
}

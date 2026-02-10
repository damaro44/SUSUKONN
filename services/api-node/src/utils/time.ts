export function nowIso(): string {
  return new Date().toISOString();
}

export function addMinutes(date: Date, minutes: number): string {
  return new Date(date.getTime() + minutes * 60_000).toISOString();
}

export function addHours(date: Date, hours: number): string {
  return new Date(date.getTime() + hours * 3_600_000).toISOString();
}

export function cycleDueDate(startDate: string, cycle: number): string {
  const start = new Date(startDate);
  const due = new Date(start);
  due.setMonth(start.getMonth() + (cycle - 1));
  return due.toISOString();
}

export function cycleGraceDate(startDate: string, cycle: number, graceDays: number): string {
  const due = new Date(cycleDueDate(startDate, cycle));
  due.setDate(due.getDate() + graceDays);
  return due.toISOString();
}

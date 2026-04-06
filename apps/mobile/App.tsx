import { StatusBar } from "expo-status-bar";
import React, { useMemo, useState } from "react";
import {
  Alert,
  Platform,
  Pressable,
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View
} from "react-native";
import * as Linking from "expo-linking";
import {
  API_BASE_URL,
  apiCall,
  AuditItem,
  AuthSession,
  DashboardPayload,
  EclairRole,
  isApiError,
  login,
  TrainingPlan
} from "./src/api/client";

type Language = "en" | "fr";

type Permission = "refresh" | "createAudit" | "createTraining" | "downloadReports";

const ROLE_PERMISSIONS: Record<EclairRole, Permission[]> = {
  super_admin: ["refresh", "createAudit", "createTraining", "downloadReports"],
  compliance_officer: ["refresh", "createAudit", "createTraining", "downloadReports"],
  auditor: ["refresh", "downloadReports"],
  training_manager: ["refresh", "createTraining"]
};

const I18N = {
  en: {
    title: "Eclair Technology Assistance",
    subtitle: "Cross-platform MVP (iOS, Android, Web)",
    apiUrl: "API URL",
    login: "Sign in",
    logout: "Sign out",
    email: "Email",
    password: "Password",
    dashboard: "Dashboard",
    audits: "Audits",
    training: "Training",
    reports: "Reports",
    capabilities: "Role Capabilities",
    allowed: "Allowed",
    restricted: "Restricted",
    refresh: "Refresh live data",
    createAudit: "Create audit",
    createTraining: "Create training",
    exportCsv: "Download CSV",
    exportPdf: "Download PDF",
    standard: "Standard",
    severity: "Severity",
    finding: "Finding",
    owner: "Owner",
    dueDate: "Due Date (YYYY-MM-DD)",
    program: "Program",
    audience: "Audience",
    mode: "Mode",
    target: "Target Completion (%)",
    objective: "Objective",
    openFindings: "Open Findings",
    riskScore: "Risk Score",
    readiness: "Readiness",
    trainingPrograms: "Training Programs",
    noData: "No data",
    status: "Status",
    role: "Role",
    createSuccessAudit: "Audit created successfully",
    createSuccessTraining: "Training plan created successfully",
    downloadSuccess: "Report download started",
    notAllowed: "Your role is not allowed for this action",
    language: "Language",
    connected: "Connected as",
    signInPrompt: "Sign in to access the live MVP"
  },
  fr: {
    title: "Assistance Technologique Eclair",
    subtitle: "MVP multiplateforme (iOS, Android, Web)",
    apiUrl: "URL API",
    login: "Se connecter",
    logout: "Se deconnecter",
    email: "Email",
    password: "Mot de passe",
    dashboard: "Tableau de bord",
    audits: "Audits",
    training: "Formation",
    reports: "Rapports",
    capabilities: "Capacites du role",
    allowed: "Autorise",
    restricted: "Restreint",
    refresh: "Rafraichir les donnees",
    createAudit: "Creer un audit",
    createTraining: "Creer une formation",
    exportCsv: "Telecharger CSV",
    exportPdf: "Telecharger PDF",
    standard: "Norme",
    severity: "Severite",
    finding: "Constat",
    owner: "Responsable",
    dueDate: "Date limite (AAAA-MM-JJ)",
    program: "Programme",
    audience: "Public cible",
    mode: "Mode",
    target: "Objectif de completion (%)",
    objective: "Objectif",
    openFindings: "Constats ouverts",
    riskScore: "Score de risque",
    readiness: "Preparation",
    trainingPrograms: "Programmes de formation",
    noData: "Aucune donnee",
    status: "Statut",
    role: "Role",
    createSuccessAudit: "Audit cree avec succes",
    createSuccessTraining: "Plan de formation cree avec succes",
    downloadSuccess: "Telechargement du rapport demarre",
    notAllowed: "Votre role n'est pas autorise pour cette action",
    language: "Langue",
    connected: "Connecte en tant que",
    signInPrompt: "Connectez-vous pour acceder au MVP en direct"
  }
} as const;

const severityOptions: Array<AuditItem["severity"]> = ["Critical", "High", "Medium", "Low"];
const modeOptions: Array<TrainingPlan["mode"]> = ["In-person", "Hybrid", "Virtual"];

export default function App() {
  const [language, setLanguage] = useState<Language>("en");
  const [apiBaseUrl, setApiBaseUrl] = useState(API_BASE_URL);
  const [session, setSession] = useState<AuthSession | null>(null);
  const [loading, setLoading] = useState(false);

  const [email, setEmail] = useState("admin@eclair.tech");
  const [password, setPassword] = useState("Admin@2026");

  const [dashboard, setDashboard] = useState<DashboardPayload | null>(null);
  const [audits, setAudits] = useState<AuditItem[]>([]);
  const [trainings, setTrainings] = useState<TrainingPlan[]>([]);

  const [auditStandard, setAuditStandard] = useState("PARAE Control P-07");
  const [auditSeverity, setAuditSeverity] = useState<AuditItem["severity"]>("High");
  const [auditFinding, setAuditFinding] = useState("");
  const [auditOwner, setAuditOwner] = useState("ICT Directorate");
  const [auditDueDate, setAuditDueDate] = useState("2026-12-31");

  const [trainingProgram, setTrainingProgram] = useState("Responsible AI Public Services");
  const [trainingAudience, setTrainingAudience] = useState("Service teams");
  const [trainingMode, setTrainingMode] = useState<TrainingPlan["mode"]>("Hybrid");
  const [trainingTarget, setTrainingTarget] = useState("90");
  const [trainingObjective, setTrainingObjective] = useState("");

  const t = I18N[language];
  const role = session?.user.role;

  const permissions = useMemo(() => {
    return role ? ROLE_PERMISSIONS[role] : [];
  }, [role]);

  const allowed = permissions;
  const restricted = (["refresh", "createAudit", "createTraining", "downloadReports"] as Permission[]).filter(
    permission => !permissions.includes(permission)
  );

  const can = (permission: Permission) => permissions.includes(permission);

  const api = async <T,>(path: string, method: "GET" | "POST" = "GET", body?: unknown): Promise<T> => {
    if (!session?.token) {
      throw new Error(t.signInPrompt);
    }

    return apiCall<T>(path, {
      method,
      token: session.token,
      body
    });
  };

  const handleError = (error: unknown) => {
    if (isApiError(error)) {
      Alert.alert("Error", error.error.message);
      return;
    }
    Alert.alert("Error", String(error));
  };

  const refreshAll = async () => {
    if (!session?.token) return;
    setLoading(true);
    try {
      const [dashboardData, auditData, trainingData] = await Promise.all([
        api<DashboardPayload>("/dashboard"),
        api<AuditItem[]>("/compliance/audits"),
        api<TrainingPlan[]>("/training/plans")
      ]);
      setDashboard(dashboardData);
      setAudits(auditData);
      setTrainings(trainingData);
    } catch (error) {
      handleError(error);
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async () => {
    setLoading(true);
    try {
      const nextSession = await login(email, password);
      setSession(nextSession);
      await refreshAllWith(nextSession);
    } catch (error) {
      handleError(error);
    } finally {
      setLoading(false);
    }
  };

  const refreshAllWith = async (authSession: AuthSession) => {
    const [dashboardData, auditData, trainingData] = await Promise.all([
      apiCall<DashboardPayload>("/dashboard", { token: authSession.token }),
      apiCall<AuditItem[]>("/compliance/audits", { token: authSession.token }),
      apiCall<TrainingPlan[]>("/training/plans", { token: authSession.token })
    ]);
    setDashboard(dashboardData);
    setAudits(auditData);
    setTrainings(trainingData);
  };

  const handleCreateAudit = async () => {
    if (!can("createAudit")) {
      Alert.alert("RBAC", t.notAllowed);
      return;
    }

    try {
      await api("/compliance/audits", "POST", {
        standard: auditStandard,
        severity: auditSeverity,
        finding: auditFinding,
        owner: auditOwner,
        dueDate: auditDueDate
      });
      Alert.alert("OK", t.createSuccessAudit);
      setAuditFinding("");
      await refreshAll();
    } catch (error) {
      handleError(error);
    }
  };

  const handleCreateTraining = async () => {
    if (!can("createTraining")) {
      Alert.alert("RBAC", t.notAllowed);
      return;
    }

    try {
      await api("/training/plans", "POST", {
        program: trainingProgram,
        audience: trainingAudience,
        mode: trainingMode,
        targetCompletion: Number(trainingTarget),
        objective: trainingObjective
      });
      Alert.alert("OK", t.createSuccessTraining);
      setTrainingObjective("");
      await refreshAll();
    } catch (error) {
      handleError(error);
    }
  };

  const handleDownloadReport = async (format: "csv" | "pdf") => {
    if (!can("downloadReports")) {
      Alert.alert("RBAC", t.notAllowed);
      return;
    }
    if (!session?.token) {
      Alert.alert("Auth", t.signInPrompt);
      return;
    }

    const url = `${apiBaseUrl}/reports/compliance?format=${format}`;

    if (Platform.OS === "web") {
      try {
        const response = await fetch(url, {
          headers: { Authorization: `Bearer ${session.token}` }
        });
        if (!response.ok) {
          throw new Error("Download failed");
        }
        const blob = await response.blob();
        const objectUrl = URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = objectUrl;
        anchor.download = `eclair-report.${format}`;
        anchor.click();
        URL.revokeObjectURL(objectUrl);
      } catch (error) {
        handleError(error);
        return;
      }
    } else {
      await Linking.openURL(url);
    }

    Alert.alert("OK", t.downloadSuccess);
  };

  const handleLogout = () => {
    setSession(null);
    setDashboard(null);
    setAudits([]);
    setTrainings([]);
  };

  const permissionLabel = (permission: Permission) => {
    if (permission === "refresh") return t.refresh;
    if (permission === "createAudit") return t.createAudit;
    if (permission === "createTraining") return t.createTraining;
    return t.reports;
  };

  return (
    <SafeAreaView style={styles.safe}>
      <StatusBar style="light" />
      <ScrollView contentContainerStyle={styles.container}>
        <View style={styles.headerCard}>
          <Text style={styles.title}>{t.title}</Text>
          <Text style={styles.subtitle}>{t.subtitle}</Text>

          <Row>
            <Text style={styles.label}>{t.language}</Text>
            <Pressable style={[styles.chip, language === "en" && styles.chipActive]} onPress={() => setLanguage("en")}>
              <Text style={styles.chipText}>EN</Text>
            </Pressable>
            <Pressable style={[styles.chip, language === "fr" && styles.chipActive]} onPress={() => setLanguage("fr")}>
              <Text style={styles.chipText}>FR</Text>
            </Pressable>
          </Row>

          <LabeledInput label={t.apiUrl} value={apiBaseUrl} onChangeText={setApiBaseUrl} />
        </View>

        {!session ? (
          <Card title={t.login}>
            <LabeledInput label={t.email} value={email} onChangeText={setEmail} />
            <LabeledInput label={t.password} value={password} onChangeText={setPassword} secureTextEntry />
            <PrimaryButton label={t.login} onPress={handleLogin} disabled={loading} />
          </Card>
        ) : (
          <>
            <Card title={t.dashboard}>
              <Text style={styles.muted}>
                {t.connected} {session.user.fullName} ({t.role}: {session.user.role})
              </Text>
              <Row>
                <PrimaryButton label={t.logout} onPress={handleLogout} />
                <SecondaryButton label={t.refresh} onPress={refreshAll} disabled={!can("refresh") || loading} />
              </Row>

              <SummaryRow label={t.readiness} value={String(dashboard?.readinessScore ?? t.noData)} />
              <SummaryRow label={t.riskScore} value={String(dashboard?.riskScore ?? t.noData)} />
              <SummaryRow label={t.openFindings} value={String(dashboard?.openAuditFindings ?? t.noData)} />
              <SummaryRow label={t.trainingPrograms} value={String(dashboard?.trainingPrograms ?? t.noData)} />
            </Card>

            <Card title={t.capabilities}>
              <Text style={styles.sectionTitle}>{t.allowed}</Text>
              {allowed.map(permission => (
                <Text key={`allowed-${permission}`} style={styles.listItem}>
                  - {permissionLabel(permission)}
                </Text>
              ))}
              <Text style={styles.sectionTitle}>{t.restricted}</Text>
              {restricted.map(permission => (
                <Text key={`restricted-${permission}`} style={styles.listItem}>
                  - {permissionLabel(permission)}
                </Text>
              ))}
            </Card>

            <Card title={t.audits}>
              <LabeledInput label={t.standard} value={auditStandard} onChangeText={setAuditStandard} />
              <Segment
                label={t.severity}
                value={auditSeverity}
                options={severityOptions}
                onChange={value => setAuditSeverity(value as AuditItem["severity"])}
              />
              <LabeledInput label={t.finding} value={auditFinding} onChangeText={setAuditFinding} multiline />
              <LabeledInput label={t.owner} value={auditOwner} onChangeText={setAuditOwner} />
              <LabeledInput label={t.dueDate} value={auditDueDate} onChangeText={setAuditDueDate} />
              <PrimaryButton label={t.createAudit} onPress={handleCreateAudit} disabled={!can("createAudit")} />

              {audits.map(item => (
                <View key={item.id} style={styles.block}>
                  <Text style={styles.blockTitle}>{item.standard}</Text>
                  <Text style={styles.blockSub}>
                    {item.severity} - {item.status}
                  </Text>
                  <Text style={styles.blockSub}>{item.finding}</Text>
                </View>
              ))}
            </Card>

            <Card title={t.training}>
              <LabeledInput label={t.program} value={trainingProgram} onChangeText={setTrainingProgram} />
              <LabeledInput label={t.audience} value={trainingAudience} onChangeText={setTrainingAudience} />
              <Segment
                label={t.mode}
                value={trainingMode}
                options={modeOptions}
                onChange={value => setTrainingMode(value as TrainingPlan["mode"])}
              />
              <LabeledInput label={t.target} value={trainingTarget} onChangeText={setTrainingTarget} />
              <LabeledInput label={t.objective} value={trainingObjective} onChangeText={setTrainingObjective} multiline />
              <PrimaryButton label={t.createTraining} onPress={handleCreateTraining} disabled={!can("createTraining")} />

              {trainings.map(item => (
                <View key={item.id} style={styles.block}>
                  <Text style={styles.blockTitle}>{item.program}</Text>
                  <Text style={styles.blockSub}>
                    {item.mode} - {item.targetCompletion}%
                  </Text>
                  <Text style={styles.blockSub}>{item.objective}</Text>
                </View>
              ))}
            </Card>

            <Card title={t.reports}>
              <Row>
                <PrimaryButton
                  label={t.exportCsv}
                  onPress={() => handleDownloadReport("csv")}
                  disabled={!can("downloadReports")}
                />
                <SecondaryButton
                  label={t.exportPdf}
                  onPress={() => handleDownloadReport("pdf")}
                  disabled={!can("downloadReports")}
                />
              </Row>
            </Card>
          </>
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <View style={styles.card}>
      <Text style={styles.cardTitle}>{title}</Text>
      {children}
    </View>
  );
}

function Row({ children }: { children: React.ReactNode }) {
  return <View style={styles.row}>{children}</View>;
}

function LabeledInput(props: {
  label: string;
  value: string;
  onChangeText: (value: string) => void;
  secureTextEntry?: boolean;
  multiline?: boolean;
}) {
  return (
    <View style={styles.inputWrap}>
      <Text style={styles.label}>{props.label}</Text>
      <TextInput
        value={props.value}
        onChangeText={props.onChangeText}
        secureTextEntry={props.secureTextEntry}
        multiline={props.multiline}
        style={[styles.input, props.multiline ? styles.inputMultiline : null]}
        placeholderTextColor="#6d7f90"
      />
    </View>
  );
}

function Segment({
  label,
  value,
  options,
  onChange
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (next: string) => void;
}) {
  return (
    <View style={styles.inputWrap}>
      <Text style={styles.label}>{label}</Text>
      <Row>
        {options.map(option => (
          <Pressable key={option} style={[styles.chip, value === option && styles.chipActive]} onPress={() => onChange(option)}>
            <Text style={styles.chipText}>{option}</Text>
          </Pressable>
        ))}
      </Row>
    </View>
  );
}

function SummaryRow({ label, value }: { label: string; value: string }) {
  return (
    <View style={styles.summaryRow}>
      <Text style={styles.summaryLabel}>{label}</Text>
      <Text style={styles.summaryValue}>{value}</Text>
    </View>
  );
}

function PrimaryButton({
  label,
  onPress,
  disabled
}: {
  label: string;
  onPress: () => void;
  disabled?: boolean;
}) {
  return (
    <Pressable style={[styles.primaryButton, disabled && styles.disabledButton]} onPress={onPress} disabled={disabled}>
      <Text style={styles.primaryButtonText}>{label}</Text>
    </Pressable>
  );
}

function SecondaryButton({
  label,
  onPress,
  disabled
}: {
  label: string;
  onPress: () => void;
  disabled?: boolean;
}) {
  return (
    <Pressable style={[styles.secondaryButton, disabled && styles.disabledButton]} onPress={onPress} disabled={disabled}>
      <Text style={styles.secondaryButtonText}>{label}</Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  safe: {
    flex: 1,
    backgroundColor: "#f3f7fb"
  },
  container: {
    padding: 14,
    gap: 12
  },
  headerCard: {
    backgroundColor: "#0C3C64",
    borderRadius: 12,
    padding: 12,
    gap: 8
  },
  title: {
    color: "#fff",
    fontSize: 20,
    fontWeight: "700"
  },
  subtitle: {
    color: "#d2e5f8"
  },
  card: {
    backgroundColor: "#fff",
    borderRadius: 12,
    borderWidth: 1,
    borderColor: "#d2e0ee",
    padding: 12,
    gap: 10
  },
  cardTitle: {
    color: "#0C3C64",
    fontWeight: "700",
    fontSize: 17
  },
  row: {
    flexDirection: "row",
    flexWrap: "wrap",
    alignItems: "center",
    gap: 8
  },
  inputWrap: {
    gap: 6
  },
  label: {
    color: "#0C3C64",
    fontWeight: "600",
    fontSize: 13
  },
  input: {
    borderWidth: 1,
    borderColor: "#bfd3e6",
    borderRadius: 10,
    paddingHorizontal: 10,
    paddingVertical: 8,
    color: "#162636",
    backgroundColor: "#fcfdff"
  },
  inputMultiline: {
    minHeight: 72,
    textAlignVertical: "top"
  },
  primaryButton: {
    backgroundColor: "#0C3C64",
    borderRadius: 10,
    paddingHorizontal: 12,
    paddingVertical: 9
  },
  primaryButtonText: {
    color: "#ffffff",
    fontWeight: "700"
  },
  secondaryButton: {
    backgroundColor: "#deebf7",
    borderRadius: 10,
    paddingHorizontal: 12,
    paddingVertical: 9
  },
  secondaryButtonText: {
    color: "#0C3C64",
    fontWeight: "700"
  },
  disabledButton: {
    opacity: 0.5
  },
  chip: {
    backgroundColor: "#e0ebf6",
    borderRadius: 999,
    paddingHorizontal: 10,
    paddingVertical: 7
  },
  chipActive: {
    backgroundColor: "#0C3C64"
  },
  chipText: {
    color: "#0C3C64",
    fontWeight: "700",
    fontSize: 12
  },
  summaryRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    backgroundColor: "#eff5fb",
    borderRadius: 10,
    paddingHorizontal: 10,
    paddingVertical: 8
  },
  summaryLabel: {
    color: "#506273",
    fontSize: 13
  },
  summaryValue: {
    color: "#0C3C64",
    fontWeight: "700",
    fontSize: 16
  },
  muted: {
    color: "#506273"
  },
  sectionTitle: {
    color: "#0C3C64",
    fontWeight: "700"
  },
  listItem: {
    color: "#334a60",
    fontSize: 13
  },
  block: {
    borderWidth: 1,
    borderColor: "#d7e4f0",
    backgroundColor: "#fbfdff",
    borderRadius: 10,
    padding: 10,
    gap: 6
  },
  blockTitle: {
    color: "#0C3C64",
    fontWeight: "700",
    fontSize: 13
  },
  blockSub: {
    color: "#495d70",
    fontSize: 12
  }
});

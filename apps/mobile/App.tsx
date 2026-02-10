import { StatusBar } from "expo-status-bar";
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Alert,
  Modal,
  Pressable,
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Switch,
  Text,
  TextInput,
  View,
} from "react-native";
import Svg, { Circle, Path, Rect } from "react-native-svg";
import { CURRENCIES, PAYOUT_REASONS, AuthUserView } from "@susukonnect/shared";
import {
  apiCall,
  AuthSession,
  isMfaRequiredError,
  MfaChallengePayload,
} from "./src/api/client";

type TabId =
  | "dashboard"
  | "groups"
  | "contributions"
  | "payouts"
  | "chat"
  | "calendar"
  | "notifications"
  | "security"
  | "admin";

type Group = {
  id: string;
  name: string;
  description: string;
  communityType: string;
  location: string;
  currency: string;
  contributionAmount: number;
  payoutOrderLogic: string;
  status: string;
  cycle: number;
  memberIds: string[];
  leaderId: string;
  joinRequests: string[];
};

type Contribution = {
  id: string;
  groupId: string;
  cycle: number;
  status: "pending" | "late" | "paid";
  amount: number;
  userId: string;
  dueDate: string;
};

type Payout = {
  id: string;
  groupId: string;
  cycle: number;
  recipientId: string;
  status: string;
  amount: number;
  currency: string;
  reason: string;
  requestedAt: string;
  recipientMfaConfirmed: boolean;
};

type ChatMessage = {
  id: string;
  groupId: string;
  userId: string;
  content: string;
  type: "message" | "announcement";
  pinned: boolean;
  createdAt: string;
};

type CalendarEvent = {
  id: string;
  date: string;
  title: string;
  type: string;
  groupName: string;
};

type AppNotification = {
  id: string;
  title: string;
  body: string;
  type: string;
  read: boolean;
  createdAt: string;
};

type DashboardPayload = {
  summary: {
    activeGroups: number;
    pendingContributions: number;
    receivedPayouts: number;
    unreadNotifications: number;
  };
};

type AdminOverview = {
  pendingKyc: Array<{ id: string; fullName: string; email: string; kyc: { status: string } }>;
  lateContributions: Contribution[];
  openDisputes: Array<{ id: string; summary: string; groupId: string; status: string }>;
  groups: Group[];
};

type MfaOptions = {
  challengeId?: string;
  code?: string;
};

export default function App() {
  const [session, setSession] = useState<AuthSession | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>("dashboard");
  const [loading, setLoading] = useState(false);
  const [deviceId] = useState(() => `rn_${Math.random().toString(36).slice(2, 12)}`);

  const [loginEmail, setLoginEmail] = useState("admin@susukonnect.app");
  const [loginPassword, setLoginPassword] = useState("Admin@2026");

  const [registerName, setRegisterName] = useState("");
  const [registerEmail, setRegisterEmail] = useState("");
  const [registerPhone, setRegisterPhone] = useState("");
  const [registerPassword, setRegisterPassword] = useState("");
  const [registerRole, setRegisterRole] = useState<"member" | "leader">("member");

  const [mfaVisible, setMfaVisible] = useState(false);
  const [mfaCodeInput, setMfaCodeInput] = useState("");
  const [mfaChallenge, setMfaChallenge] = useState<MfaChallengePayload | null>(null);
  const [mfaPurpose, setMfaPurpose] = useState("");
  const mfaResolverRef = useRef<((value: string | null) => void) | null>(null);

  const [dashboard, setDashboard] = useState<DashboardPayload | null>(null);
  const [groups, setGroups] = useState<Group[]>([]);
  const [contributions, setContributions] = useState<Contribution[]>([]);
  const [payouts, setPayouts] = useState<Payout[]>([]);
  const [chat, setChat] = useState<ChatMessage[]>([]);
  const [calendarEvents, setCalendarEvents] = useState<CalendarEvent[]>([]);
  const [notifications, setNotifications] = useState<AppNotification[]>([]);
  const [adminOverview, setAdminOverview] = useState<AdminOverview | null>(null);

  const [selectedGroupId, setSelectedGroupId] = useState<string>("");
  const [selectedReason, setSelectedReason] = useState<string>(PAYOUT_REASONS[0]);
  const [chatMessage, setChatMessage] = useState("");

  const [kycIdType, setKycIdType] = useState("Passport");
  const [kycIdNumber, setKycIdNumber] = useState("");
  const [kycDob, setKycDob] = useState("1990-01-01");
  const [kycSelfie, setKycSelfie] = useState("");
  const [kycAddress, setKycAddress] = useState("");

  const [securityMfa, setSecurityMfa] = useState(true);
  const [securityBiometric, setSecurityBiometric] = useState(false);

  const [paymentType, setPaymentType] = useState<"bank" | "debit" | "paypal" | "cashapp">("bank");
  const [paymentLabel, setPaymentLabel] = useState("");
  const [paymentTail, setPaymentTail] = useState("");
  const [paymentToken, setPaymentToken] = useState("");
  const [paymentAutoDebit, setPaymentAutoDebit] = useState(false);

  const [newGroupName, setNewGroupName] = useState("");
  const [newGroupDescription, setNewGroupDescription] = useState("");
  const [newGroupCommunity, setNewGroupCommunity] = useState("General");
  const [newGroupLocation, setNewGroupLocation] = useState("New York");
  const [newGroupStartDate, setNewGroupStartDate] = useState("2026-03-01");
  const [newGroupAmount, setNewGroupAmount] = useState("100");
  const [newGroupCurrency, setNewGroupCurrency] = useState<typeof CURRENCIES[number]>("USD");
  const [newGroupMembers, setNewGroupMembers] = useState("5");
  const [newGroupLogic, setNewGroupLogic] = useState<"fixed" | "voting" | "priority">("fixed");
  const [newGroupGrace, setNewGroupGrace] = useState("3");
  const [newGroupLeaderApproval, setNewGroupLeaderApproval] = useState(true);
  const [newGroupRules, setNewGroupRules] = useState("Contribute by due date; respect group rules.");

  const authUser = session?.user ?? null;
  const tabList = useMemo(() => {
    const base: Array<{ id: TabId; label: string }> = [
      { id: "dashboard", label: "Dashboard" },
      { id: "groups", label: "Groups" },
      { id: "contributions", label: "Contributions" },
      { id: "payouts", label: "Payouts" },
      { id: "chat", label: "Chat" },
      { id: "calendar", label: "Calendar" },
      { id: "notifications", label: "Alerts" },
      { id: "security", label: "Security" },
    ];
    if (authUser?.role === "admin") {
      base.push({ id: "admin", label: "Admin" });
    }
    return base;
  }, [authUser?.role]);

  const selectedGroup = groups.find((group) => group.id === selectedGroupId);
  const selectedGroupPayout = payouts.find(
    (entry) => entry.groupId === selectedGroupId && selectedGroup && entry.cycle === selectedGroup.cycle
  );

  const openMfaPrompt = useCallback((challenge: MfaChallengePayload, purpose: string) => {
    setMfaChallenge(challenge);
    setMfaPurpose(purpose);
    setMfaCodeInput("");
    setMfaVisible(true);
    return new Promise<string | null>((resolve) => {
      mfaResolverRef.current = resolve;
    });
  }, []);

  const closeMfaPrompt = useCallback((value: string | null) => {
    if (mfaResolverRef.current) {
      mfaResolverRef.current(value);
      mfaResolverRef.current = null;
    }
    setMfaVisible(false);
    setMfaChallenge(null);
    setMfaPurpose("");
    setMfaCodeInput("");
  }, []);

  const runWithMfa = useCallback(
    async <T,>(purpose: string, executor: (mfa?: MfaOptions) => Promise<T>): Promise<T | null> => {
      try {
        return await executor();
      } catch (error) {
        if (!isMfaRequiredError(error)) {
          throw error;
        }
        const challenge = error.data as MfaChallengePayload;
        const code = await openMfaPrompt(challenge, purpose);
        if (!code) {
          return null;
        }
        return executor({ challengeId: challenge.challengeId, code });
      }
    },
    [openMfaPrompt]
  );

  const handleError = (error: unknown) => {
    const apiError = error as { error?: { message?: string } };
    Alert.alert("Request failed", apiError?.error?.message ?? "Unexpected error.");
  };

  const refreshData = useCallback(
    async (tab: TabId = activeTab) => {
      if (!session?.token) {
        return;
      }
      setLoading(true);
      try {
        if (tab === "dashboard") {
          const data = await apiCall<DashboardPayload>("/dashboard", { token: session.token });
          setDashboard(data);
        }
        if (tab === "groups" || tab === "chat" || tab === "payouts" || tab === "contributions") {
          const data = await apiCall<Group[]>("/groups", { token: session.token });
          setGroups(data);
          if (!selectedGroupId && data.length > 0) {
            setSelectedGroupId(data[0].id);
          }
        }
        if (tab === "contributions") {
          const data = await apiCall<Contribution[]>("/contributions", { token: session.token });
          setContributions(data);
        }
        if (tab === "payouts") {
          const data = await apiCall<Payout[]>("/payouts", { token: session.token });
          setPayouts(data);
        }
        if (tab === "chat" && selectedGroupId) {
          const data = await apiCall<ChatMessage[]>(`/groups/${selectedGroupId}/chat`, {
            token: session.token,
          });
          setChat(data);
        }
        if (tab === "calendar") {
          const data = await apiCall<CalendarEvent[]>("/calendar/events", { token: session.token });
          setCalendarEvents(data);
        }
        if (tab === "notifications") {
          const data = await apiCall<AppNotification[]>("/notifications", {
            token: session.token,
          });
          setNotifications(data);
        }
        if (tab === "admin" && authUser?.role === "admin") {
          const data = await apiCall<AdminOverview>("/admin/overview", { token: session.token });
          setAdminOverview(data);
        }
      } catch (error) {
        handleError(error);
      } finally {
        setLoading(false);
      }
    },
    [activeTab, authUser?.role, selectedGroupId, selectedGroupId, session?.token]
  );

  useEffect(() => {
    if (!session?.token) {
      return;
    }
    refreshData(activeTab).catch(handleError);
  }, [activeTab, refreshData, session?.token]);

  useEffect(() => {
    if (authUser) {
      setSecurityMfa(authUser.mfaEnabled);
      setSecurityBiometric(authUser.biometricEnabled);
    }
  }, [authUser]);

  const doLogin = async () => {
    try {
      const loginResult = await apiCall<{
        requiresMfa: boolean;
        challenge?: MfaChallengePayload;
        tokens?: { accessToken: string; expiresAt: string };
        user?: AuthUserView;
      }>("/auth/login", {
        method: "POST",
        body: {
          email: loginEmail,
          password: loginPassword,
          deviceId,
        },
      });
      if (!loginResult.requiresMfa && loginResult.tokens && loginResult.user) {
        setSession({
          token: loginResult.tokens.accessToken,
          expiresAt: loginResult.tokens.expiresAt,
          user: loginResult.user,
        });
        setActiveTab("dashboard");
        return;
      }
    } catch (error) {
      if (!isMfaRequiredError(error)) {
        handleError(error);
        return;
      }
      const challenge = error.data as MfaChallengePayload;
      const code = await openMfaPrompt(challenge, "Login confirmation");
      if (!code) {
        return;
      }
      try {
        const verify = await apiCall<{
          tokens: { accessToken: string; expiresAt: string };
          user: AuthUserView;
        }>("/auth/mfa/verify", {
          method: "POST",
          body: {
            challengeId: challenge.challengeId,
            code,
            deviceId,
          },
        });
        setSession({
          token: verify.tokens.accessToken,
          expiresAt: verify.tokens.expiresAt,
          user: verify.user,
        });
        setActiveTab("dashboard");
      } catch (verifyError) {
        handleError(verifyError);
      }
    }
  };

  const doBiometricLogin = async () => {
    try {
      const result = await apiCall<{
        tokens: { accessToken: string; expiresAt: string };
        user: AuthUserView;
      }>("/auth/biometric-login", {
        method: "POST",
        body: {
          email: loginEmail,
          deviceId,
        },
      });
      setSession({
        token: result.tokens.accessToken,
        expiresAt: result.tokens.expiresAt,
        user: result.user,
      });
      setActiveTab("dashboard");
    } catch (error) {
      handleError(error);
    }
  };

  const doRegister = async () => {
    try {
      await apiCall("/auth/register", {
        method: "POST",
        body: {
          fullName: registerName,
          email: registerEmail,
          phone: registerPhone,
          password: registerPassword,
          role: registerRole,
          acceptTerms: true,
        },
      });
      Alert.alert("Success", "Account created. Please login.");
      setRegisterName("");
      setRegisterEmail("");
      setRegisterPhone("");
      setRegisterPassword("");
    } catch (error) {
      handleError(error);
    }
  };

  const doLogout = async () => {
    if (!session?.token) {
      return;
    }
    try {
      await apiCall("/auth/logout", {
        method: "POST",
        token: session.token,
      });
    } catch {
      // no-op
    } finally {
      setSession(null);
      setDashboard(null);
      setGroups([]);
      setContributions([]);
      setPayouts([]);
      setChat([]);
      setCalendarEvents([]);
      setNotifications([]);
      setAdminOverview(null);
    }
  };

  const createGroup = async () => {
    if (!session?.token) {
      return;
    }
    try {
      await apiCall("/groups", {
        method: "POST",
        token: session.token,
        body: {
          name: newGroupName,
          description: newGroupDescription,
          communityType: newGroupCommunity,
          location: newGroupLocation,
          startDate: newGroupStartDate,
          contributionAmount: Number(newGroupAmount),
          currency: newGroupCurrency,
          totalMembers: Number(newGroupMembers),
          payoutOrderLogic: newGroupLogic,
          gracePeriodDays: Number(newGroupGrace),
          requiresLeaderApproval: newGroupLeaderApproval,
          rules: newGroupRules,
        },
      });
      Alert.alert("Success", "Group created.");
      await refreshData("groups");
    } catch (error) {
      handleError(error);
    }
  };

  const joinGroup = async (groupId: string) => {
    if (!session?.token) {
      return;
    }
    try {
      await apiCall(`/groups/${groupId}/join`, { method: "POST", token: session.token });
      await refreshData("groups");
    } catch (error) {
      handleError(error);
    }
  };

  const payContribution = async (contributionId: string) => {
    if (!session?.token || !authUser?.paymentMethods.length) {
      Alert.alert("Payment method required", "Add a payment method first.");
      return;
    }
    const methodId = authUser.paymentMethods[0].id;
    try {
      await runWithMfa("Pay contribution", (mfa) =>
        apiCall(`/contributions/${contributionId}/pay`, {
          method: "POST",
          token: session.token,
          body: {
            methodId,
            enableAutoDebit: false,
            mfaChallengeId: mfa?.challengeId,
            mfaCode: mfa?.code,
          },
        })
      );
      await refreshData("contributions");
      await refreshData("dashboard");
    } catch (error) {
      handleError(error);
    }
  };

  const requestPayout = async () => {
    if (!session?.token || !selectedGroupId) {
      return;
    }
    try {
      await apiCall(`/groups/${selectedGroupId}/payouts/request`, {
        method: "POST",
        token: session.token,
        body: {
          reason: selectedReason,
          customReason: "",
        },
      });
      await refreshData("payouts");
    } catch (error) {
      handleError(error);
    }
  };

  const approvePayout = async (payoutId: string) => {
    if (!session?.token) {
      return;
    }
    try {
      await runWithMfa("Approve payout", (mfa) =>
        apiCall(`/payouts/${payoutId}/approve`, {
          method: "POST",
          token: session.token,
          body: {
            mfaChallengeId: mfa?.challengeId,
            mfaCode: mfa?.code,
          },
        })
      );
      await refreshData("payouts");
    } catch (error) {
      handleError(error);
    }
  };

  const confirmRecipient = async (payoutId: string) => {
    if (!session?.token) {
      return;
    }
    try {
      await runWithMfa("Confirm recipient", (mfa) =>
        apiCall(`/payouts/${payoutId}/confirm-recipient`, {
          method: "POST",
          token: session.token,
          body: {
            mfaChallengeId: mfa?.challengeId,
            mfaCode: mfa?.code,
          },
        })
      );
      await refreshData("payouts");
    } catch (error) {
      handleError(error);
    }
  };

  const releasePayout = async (payoutId: string) => {
    if (!session?.token) {
      return;
    }
    try {
      await runWithMfa("Release payout", (mfa) =>
        apiCall(`/payouts/${payoutId}/release`, {
          method: "POST",
          token: session.token,
          body: {
            mfaChallengeId: mfa?.challengeId,
            mfaCode: mfa?.code,
          },
        })
      );
      await refreshData("payouts");
      await refreshData("dashboard");
    } catch (error) {
      handleError(error);
    }
  };

  const postChat = async () => {
    if (!session?.token || !selectedGroupId || !chatMessage.trim()) {
      return;
    }
    try {
      await apiCall(`/groups/${selectedGroupId}/chat`, {
        method: "POST",
        token: session.token,
        body: {
          content: chatMessage,
          announcement: false,
          pin: false,
        },
      });
      setChatMessage("");
      await refreshData("chat");
    } catch (error) {
      handleError(error);
    }
  };

  const markRead = async (notificationId: string) => {
    if (!session?.token) {
      return;
    }
    try {
      await apiCall(`/notifications/${notificationId}/read`, {
        method: "POST",
        token: session.token,
      });
      await refreshData("notifications");
    } catch (error) {
      handleError(error);
    }
  };

  const markAllRead = async () => {
    if (!session?.token) {
      return;
    }
    try {
      await apiCall("/notifications/read-all", { method: "POST", token: session.token });
      await refreshData("notifications");
    } catch (error) {
      handleError(error);
    }
  };

  const submitKyc = async () => {
    if (!session?.token) {
      return;
    }
    try {
      await apiCall("/me/kyc", {
        method: "POST",
        token: session.token,
        body: {
          idType: kycIdType,
          idNumber: kycIdNumber,
          dob: kycDob,
          selfieToken: kycSelfie,
          address: kycAddress,
        },
      });
      Alert.alert("Submitted", "KYC submitted for review.");
      setKycIdNumber("");
      setKycSelfie("");
    } catch (error) {
      handleError(error);
    }
  };

  const updateSecurity = async () => {
    if (!session?.token) {
      return;
    }
    try {
      const user = await runWithMfa("Update security settings", (mfa) =>
        apiCall<AuthUserView>("/me/security", {
          method: "PATCH",
          token: session.token,
          body: {
            mfaEnabled: securityMfa,
            biometricEnabled: securityBiometric,
            mfaChallengeId: mfa?.challengeId,
            mfaCode: mfa?.code,
          },
        })
      );
      if (user) {
        setSession((previous) =>
          previous
            ? {
                ...previous,
                user,
              }
            : previous
        );
      }
    } catch (error) {
      handleError(error);
    }
  };

  const addPaymentMethod = async () => {
    if (!session?.token) {
      return;
    }
    try {
      await runWithMfa("Add payment method", (mfa) =>
        apiCall("/me/payment-methods", {
          method: "POST",
          token: session.token,
          body: {
            type: paymentType,
            label: paymentLabel,
            identifierTail: paymentTail,
            providerToken: paymentToken || `sandbox_${paymentType}_${paymentTail}`,
            autoDebit: paymentAutoDebit,
            mfaChallengeId: mfa?.challengeId,
            mfaCode: mfa?.code,
          },
        })
      );
      Alert.alert("Success", "Payment method added.");
      const me = await apiCall<AuthUserView>("/auth/me", { token: session.token });
      setSession((previous) => (previous ? { ...previous, user: me } : previous));
      setPaymentLabel("");
      setPaymentTail("");
      setPaymentToken("");
    } catch (error) {
      handleError(error);
    }
  };

  const reviewKyc = async (userId: string, status: "verified" | "rejected") => {
    if (!session?.token) {
      return;
    }
    try {
      await apiCall(`/admin/kyc/${userId}/review`, {
        method: "POST",
        token: session.token,
        body: { status },
      });
      await refreshData("admin");
    } catch (error) {
      handleError(error);
    }
  };

  if (!session?.token) {
    return (
      <SafeAreaView style={styles.safe}>
        <StatusBar style="light" />
        <ScrollView contentContainerStyle={styles.authContainer}>
          <SusuKonnectLogo />
          <Text style={styles.title}>SusuKonnect Mobile</Text>
          <Text style={styles.subtitle}>Saving Together, Growing Together</Text>

          <Card title="Sign In">
            <Input label="Email" value={loginEmail} onChangeText={setLoginEmail} />
            <Input label="Password" value={loginPassword} onChangeText={setLoginPassword} secureTextEntry />
            <Row>
              <PrimaryButton label="Secure Login" onPress={doLogin} />
              <SecondaryButton label="Biometric" onPress={doBiometricLogin} />
            </Row>
          </Card>

          <Card title="Create Account">
            <Input label="Full name" value={registerName} onChangeText={setRegisterName} />
            <Input label="Phone" value={registerPhone} onChangeText={setRegisterPhone} />
            <Input label="Email" value={registerEmail} onChangeText={setRegisterEmail} />
            <Input label="Password" value={registerPassword} onChangeText={setRegisterPassword} secureTextEntry />
            <SegmentedSwitch
              label="Role"
              values={[
                { value: "member", label: "Member" },
                { value: "leader", label: "Leader" },
              ]}
              selectedValue={registerRole}
              onSelect={(value) => setRegisterRole(value as "member" | "leader")}
            />
            <PrimaryButton label="Register" onPress={doRegister} />
          </Card>
        </ScrollView>
        <MfaModal
          visible={mfaVisible}
          purpose={mfaPurpose}
          challenge={mfaChallenge}
          code={mfaCodeInput}
          onChangeCode={setMfaCodeInput}
          onCancel={() => closeMfaPrompt(null)}
          onConfirm={() => closeMfaPrompt(mfaCodeInput)}
        />
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.safe}>
      <StatusBar style="light" />
      <View style={styles.header}>
        <SusuKonnectMarkSmall />
        <View style={{ flex: 1 }}>
          <Text style={styles.headerTitle}>{authUser?.fullName}</Text>
          <Text style={styles.headerSubtitle}>
            {authUser?.role.toUpperCase()} • KYC: {authUser?.kyc.status}
          </Text>
        </View>
        <SecondaryButton label="Logout" onPress={doLogout} />
      </View>

      <ScrollView horizontal style={styles.tabScroll} contentContainerStyle={styles.tabRow}>
        {tabList.map((tab) => (
          <Pressable
            key={tab.id}
            style={[styles.tab, activeTab === tab.id && styles.tabActive]}
            onPress={() => setActiveTab(tab.id)}
          >
            <Text style={[styles.tabText, activeTab === tab.id && styles.tabTextActive]}>{tab.label}</Text>
          </Pressable>
        ))}
      </ScrollView>

      <ScrollView contentContainerStyle={styles.screen}>
        {loading ? <Text style={styles.loading}>Loading...</Text> : null}

        {activeTab === "dashboard" && (
          <Card title="Operational Dashboard">
            <SummaryRow label="Active groups" value={String(dashboard?.summary.activeGroups ?? 0)} />
            <SummaryRow
              label="Pending contributions"
              value={String(dashboard?.summary.pendingContributions ?? 0)}
            />
            <SummaryRow label="Received payouts" value={String(dashboard?.summary.receivedPayouts ?? 0)} />
            <SummaryRow
              label="Unread notifications"
              value={String(dashboard?.summary.unreadNotifications ?? 0)}
            />
            <PrimaryButton label="Refresh" onPress={() => refreshData("dashboard")} />
          </Card>
        )}

        {activeTab === "groups" && (
          <>
            <Card title="Your Groups">
              {groups.map((group) => (
                <View key={group.id} style={styles.listItem}>
                  <Text style={styles.listTitle}>{group.name}</Text>
                  <Text style={styles.listSubtitle}>
                    {group.communityType} • {group.location} • {group.status}
                  </Text>
                  <Text style={styles.listSubtitle}>
                    {formatMoney(group.contributionAmount, group.currency)} monthly • Cycle {group.cycle}
                  </Text>
                  {!group.memberIds.includes(authUser!.id) ? (
                    <PrimaryButton label="Join group" onPress={() => joinGroup(group.id)} />
                  ) : null}
                  <SecondaryButton label="Select" onPress={() => setSelectedGroupId(group.id)} />
                </View>
              ))}
              <PrimaryButton label="Refresh groups" onPress={() => refreshData("groups")} />
            </Card>

            <Card title="Create Group">
              <Input label="Name" value={newGroupName} onChangeText={setNewGroupName} />
              <Input
                label="Description"
                value={newGroupDescription}
                onChangeText={setNewGroupDescription}
                multiline
              />
              <Input label="Community" value={newGroupCommunity} onChangeText={setNewGroupCommunity} />
              <Input label="Location" value={newGroupLocation} onChangeText={setNewGroupLocation} />
              <Input label="Start date (YYYY-MM-DD)" value={newGroupStartDate} onChangeText={setNewGroupStartDate} />
              <Input
                label="Contribution amount"
                value={newGroupAmount}
                onChangeText={setNewGroupAmount}
                keyboardType="decimal-pad"
              />
              <SegmentedSwitch
                label="Currency"
                values={CURRENCIES.slice(0, 4).map((currency) => ({
                  value: currency,
                  label: currency,
                }))}
                selectedValue={newGroupCurrency}
                onSelect={(value) => setNewGroupCurrency(value as typeof CURRENCIES[number])}
              />
              <Input label="Total members" value={newGroupMembers} onChangeText={setNewGroupMembers} keyboardType="number-pad" />
              <SegmentedSwitch
                label="Payout logic"
                values={[
                  { value: "fixed", label: "Fixed" },
                  { value: "voting", label: "Voting" },
                  { value: "priority", label: "Priority" },
                ]}
                selectedValue={newGroupLogic}
                onSelect={(value) => setNewGroupLogic(value as "fixed" | "voting" | "priority")}
              />
              <Input
                label="Grace days"
                value={newGroupGrace}
                onChangeText={setNewGroupGrace}
                keyboardType="number-pad"
              />
              <Input label="Rules" value={newGroupRules} onChangeText={setNewGroupRules} multiline />
              <Row>
                <Text style={styles.label}>Require leader approval</Text>
                <Switch value={newGroupLeaderApproval} onValueChange={setNewGroupLeaderApproval} />
              </Row>
              <PrimaryButton label="Create group" onPress={createGroup} />
            </Card>
          </>
        )}

        {activeTab === "contributions" && (
          <Card title="Contributions">
            {contributions
              .filter((entry) => !selectedGroupId || entry.groupId === selectedGroupId)
              .map((entry) => (
                <View key={entry.id} style={styles.listItem}>
                  <Text style={styles.listTitle}>
                    {entry.groupId} • Cycle {entry.cycle}
                  </Text>
                  <Text style={styles.listSubtitle}>
                    {formatMoney(entry.amount, selectedGroup?.currency ?? "USD")} • {entry.status.toUpperCase()}
                  </Text>
                  {entry.userId === authUser?.id && entry.status !== "paid" ? (
                    <PrimaryButton label="Pay contribution" onPress={() => payContribution(entry.id)} />
                  ) : null}
                </View>
              ))}
            <PrimaryButton label="Refresh contributions" onPress={() => refreshData("contributions")} />
          </Card>
        )}

        {activeTab === "payouts" && (
          <Card title="Payout Workflow">
            <SegmentedSwitch
              label="Payout reason"
              values={PAYOUT_REASONS.slice(0, 4).map((reason) => ({ value: reason, label: reason.split(" ")[0] }))}
              selectedValue={selectedReason}
              onSelect={setSelectedReason}
            />
            <PrimaryButton label="Request payout for selected group" onPress={requestPayout} />

            {selectedGroupPayout ? (
              <View style={styles.listItem}>
                <Text style={styles.listTitle}>{selectedGroupPayout.reason}</Text>
                <Text style={styles.listSubtitle}>
                  {formatMoney(selectedGroupPayout.amount, selectedGroupPayout.currency)} •{" "}
                  {selectedGroupPayout.status.toUpperCase()}
                </Text>
                <Row>
                  <SecondaryButton label="Approve" onPress={() => approvePayout(selectedGroupPayout.id)} />
                  {selectedGroupPayout.recipientId === authUser?.id ? (
                    <SecondaryButton
                      label="Confirm recipient"
                      onPress={() => confirmRecipient(selectedGroupPayout.id)}
                    />
                  ) : null}
                  <PrimaryButton label="Release" onPress={() => releasePayout(selectedGroupPayout.id)} />
                </Row>
              </View>
            ) : (
              <Text style={styles.listSubtitle}>No cycle payout yet for selected group.</Text>
            )}

            <PrimaryButton label="Refresh payouts" onPress={() => refreshData("payouts")} />
          </Card>
        )}

        {activeTab === "chat" && (
          <Card title="Group Chat">
            <GroupPicker
              groups={groups}
              selectedGroupId={selectedGroupId}
              onSelectGroup={setSelectedGroupId}
              onRefresh={() => refreshData("chat")}
            />
            {chat.map((message) => (
              <View key={message.id} style={[styles.listItem, message.pinned ? styles.pinned : null]}>
                <Text style={styles.listTitle}>
                  {message.type.toUpperCase()} • {formatDateTime(message.createdAt)}
                </Text>
                <Text style={styles.listSubtitle}>{message.content}</Text>
              </View>
            ))}
            <Input label="Message" value={chatMessage} onChangeText={setChatMessage} multiline />
            <PrimaryButton label="Send message" onPress={postChat} />
          </Card>
        )}

        {activeTab === "calendar" && (
          <Card title="Calendar & Milestones">
            {calendarEvents.map((event) => (
              <View key={event.id} style={styles.listItem}>
                <Text style={styles.listTitle}>{event.title}</Text>
                <Text style={styles.listSubtitle}>
                  {event.groupName} • {formatDateTime(event.date)}
                </Text>
              </View>
            ))}
            <PrimaryButton label="Refresh calendar" onPress={() => refreshData("calendar")} />
          </Card>
        )}

        {activeTab === "notifications" && (
          <Card title="Smart Notifications">
            <Row>
              <PrimaryButton label="Mark all read" onPress={markAllRead} />
              <SecondaryButton label="Refresh" onPress={() => refreshData("notifications")} />
            </Row>
            {notifications.map((note) => (
              <View key={note.id} style={[styles.listItem, !note.read ? styles.unread : null]}>
                <Text style={styles.listTitle}>{note.title}</Text>
                <Text style={styles.listSubtitle}>
                  {note.body} • {formatDateTime(note.createdAt)}
                </Text>
                {!note.read ? <SecondaryButton label="Mark read" onPress={() => markRead(note.id)} /> : null}
              </View>
            ))}
          </Card>
        )}

        {activeTab === "security" && (
          <>
            <Card title="KYC">
              <Input label="ID Type" value={kycIdType} onChangeText={setKycIdType} />
              <Input label="ID Number" value={kycIdNumber} onChangeText={setKycIdNumber} />
              <Input label="DOB (YYYY-MM-DD)" value={kycDob} onChangeText={setKycDob} />
              <Input label="Selfie token" value={kycSelfie} onChangeText={setKycSelfie} />
              <Input label="Address (optional)" value={kycAddress} onChangeText={setKycAddress} />
              <PrimaryButton label="Submit KYC" onPress={submitKyc} />
            </Card>

            <Card title="Authentication controls">
              <Row>
                <Text style={styles.label}>Enable MFA</Text>
                <Switch value={securityMfa} onValueChange={setSecurityMfa} />
              </Row>
              <Row>
                <Text style={styles.label}>Enable Biometric</Text>
                <Switch value={securityBiometric} onValueChange={setSecurityBiometric} />
              </Row>
              <PrimaryButton label="Save security settings" onPress={updateSecurity} />
            </Card>

            <Card title="Payment methods">
              <SegmentedSwitch
                label="Method"
                values={[
                  { value: "bank", label: "Bank" },
                  { value: "debit", label: "Debit" },
                  { value: "paypal", label: "PayPal" },
                  { value: "cashapp", label: "CashApp" },
                ]}
                selectedValue={paymentType}
                onSelect={(value) => setPaymentType(value as "bank" | "debit" | "paypal" | "cashapp")}
              />
              <Input label="Label" value={paymentLabel} onChangeText={setPaymentLabel} />
              <Input label="Identifier tail (last 4)" value={paymentTail} onChangeText={setPaymentTail} />
              <Input
                label="Provider token ref (Stripe pm_ / PayPal payer ref)"
                value={paymentToken}
                onChangeText={setPaymentToken}
              />
              <Row>
                <Text style={styles.label}>Enable auto debit</Text>
                <Switch value={paymentAutoDebit} onValueChange={setPaymentAutoDebit} />
              </Row>
              <PrimaryButton label="Add payment method" onPress={addPaymentMethod} />
            </Card>
          </>
        )}

        {activeTab === "admin" && authUser?.role === "admin" && (
          <Card title="Admin Compliance">
            <SummaryRow label="Pending KYC" value={String(adminOverview?.pendingKyc.length ?? 0)} />
            <SummaryRow label="Late contributions" value={String(adminOverview?.lateContributions.length ?? 0)} />
            <SummaryRow label="Open disputes" value={String(adminOverview?.openDisputes.length ?? 0)} />
            <PrimaryButton label="Refresh overview" onPress={() => refreshData("admin")} />

            {adminOverview?.pendingKyc.map((item) => (
              <View key={item.id} style={styles.listItem}>
                <Text style={styles.listTitle}>{item.fullName}</Text>
                <Text style={styles.listSubtitle}>{item.email}</Text>
                <Row>
                  <SecondaryButton label="Approve" onPress={() => reviewKyc(item.id, "verified")} />
                  <SecondaryButton label="Reject" onPress={() => reviewKyc(item.id, "rejected")} />
                </Row>
              </View>
            ))}
          </Card>
        )}
      </ScrollView>

      <MfaModal
        visible={mfaVisible}
        purpose={mfaPurpose}
        challenge={mfaChallenge}
        code={mfaCodeInput}
        onChangeCode={setMfaCodeInput}
        onCancel={() => closeMfaPrompt(null)}
        onConfirm={() => closeMfaPrompt(mfaCodeInput)}
      />
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

function Input(props: {
  label: string;
  value: string;
  onChangeText: (value: string) => void;
  secureTextEntry?: boolean;
  multiline?: boolean;
  keyboardType?: "default" | "number-pad" | "decimal-pad";
}) {
  return (
    <View style={styles.inputWrap}>
      <Text style={styles.label}>{props.label}</Text>
      <TextInput
        value={props.value}
        onChangeText={props.onChangeText}
        secureTextEntry={props.secureTextEntry}
        multiline={props.multiline}
        keyboardType={props.keyboardType ?? "default"}
        style={[styles.input, props.multiline ? styles.inputMultiline : null]}
        placeholderTextColor="#6d7f90"
      />
    </View>
  );
}

function PrimaryButton({ label, onPress }: { label: string; onPress: () => void }) {
  return (
    <Pressable style={styles.primaryButton} onPress={onPress}>
      <Text style={styles.primaryButtonText}>{label}</Text>
    </Pressable>
  );
}

function SecondaryButton({ label, onPress }: { label: string; onPress: () => void }) {
  return (
    <Pressable style={styles.secondaryButton} onPress={onPress}>
      <Text style={styles.secondaryButtonText}>{label}</Text>
    </Pressable>
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

function SegmentedSwitch({
  label,
  values,
  selectedValue,
  onSelect,
}: {
  label: string;
  values: Array<{ value: string; label: string }>;
  selectedValue: string;
  onSelect: (value: string) => void;
}) {
  return (
    <View style={styles.inputWrap}>
      <Text style={styles.label}>{label}</Text>
      <View style={styles.segmentRow}>
        {values.map((item) => (
          <Pressable
            key={item.value}
            style={[styles.segment, selectedValue === item.value ? styles.segmentActive : null]}
            onPress={() => onSelect(item.value)}
          >
            <Text
              style={[styles.segmentText, selectedValue === item.value ? styles.segmentTextActive : null]}
            >
              {item.label}
            </Text>
          </Pressable>
        ))}
      </View>
    </View>
  );
}

function GroupPicker({
  groups,
  selectedGroupId,
  onSelectGroup,
  onRefresh,
}: {
  groups: Group[];
  selectedGroupId: string;
  onSelectGroup: (groupId: string) => void;
  onRefresh: () => void;
}) {
  return (
    <View style={{ marginBottom: 12 }}>
      <Text style={styles.label}>Selected group</Text>
      <ScrollView horizontal showsHorizontalScrollIndicator={false} contentContainerStyle={styles.tabRow}>
        {groups.map((group) => (
          <Pressable
            key={group.id}
            style={[styles.tab, selectedGroupId === group.id ? styles.tabActive : null]}
            onPress={() => onSelectGroup(group.id)}
          >
            <Text style={[styles.tabText, selectedGroupId === group.id ? styles.tabTextActive : null]}>
              {group.name}
            </Text>
          </Pressable>
        ))}
      </ScrollView>
      <SecondaryButton label="Refresh messages" onPress={onRefresh} />
    </View>
  );
}

function MfaModal({
  visible,
  purpose,
  challenge,
  code,
  onChangeCode,
  onCancel,
  onConfirm,
}: {
  visible: boolean;
  purpose: string;
  challenge: MfaChallengePayload | null;
  code: string;
  onChangeCode: (code: string) => void;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <Modal visible={visible} transparent animationType="fade">
      <View style={styles.modalBackdrop}>
        <View style={styles.modalCard}>
          <Text style={styles.cardTitle}>MFA verification required</Text>
          <Text style={styles.listSubtitle}>{purpose}</Text>
          {challenge?.demoCode ? (
            <Text style={styles.demoCode}>Demo code: {challenge.demoCode}</Text>
          ) : (
            <Text style={styles.listSubtitle}>Check your authenticator/SMS.</Text>
          )}
          <Input label="6-digit code" value={code} onChangeText={onChangeCode} keyboardType="number-pad" />
          <Row>
            <SecondaryButton label="Cancel" onPress={onCancel} />
            <PrimaryButton label="Confirm" onPress={onConfirm} />
          </Row>
        </View>
      </View>
    </Modal>
  );
}

function SusuKonnectLogo() {
  return (
    <View style={{ alignItems: "center", marginBottom: 14 }}>
      <SusuKonnectMarkSmall />
      <Text style={styles.brandText}>SusuKonnect</Text>
      <Text style={styles.brandSubText}>Saving Together, Growing Together</Text>
    </View>
  );
}

function SusuKonnectMarkSmall() {
  return (
    <Svg width={72} height={72} viewBox="0 0 512 512">
      <Rect x={20} y={20} width={472} height={472} rx={72} fill="#0C3C64" />
      <Rect x={28} y={28} width={456} height={456} rx={64} stroke="#083050" strokeWidth={16} />
      <Path
        d="M104 118H188L228 158V226L188 266H104"
        stroke="#E7BE63"
        strokeWidth={16}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <Path
        d="M408 118H324L284 158V354L324 394H408"
        stroke="#E7BE63"
        strokeWidth={16}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <Circle cx={96} cy={118} r={16} fill="#0C3C64" stroke="#E7BE63" strokeWidth={10} />
      <Circle cx={416} cy={118} r={16} fill="#0C3C64" stroke="#E7BE63" strokeWidth={10} />
      <Circle cx={96} cy={394} r={16} fill="#0C3C64" stroke="#E7BE63" strokeWidth={10} />
      <Circle cx={416} cy={394} r={16} fill="#0C3C64" stroke="#E7BE63" strokeWidth={10} />
    </Svg>
  );
}

function formatDateTime(value: string) {
  return new Date(value).toLocaleString();
}

function formatMoney(amount: number, currency: string): string {
  try {
    return new Intl.NumberFormat(undefined, {
      style: "currency",
      currency,
      maximumFractionDigits: 2,
    }).format(amount);
  } catch {
    return `${currency} ${amount.toFixed(2)}`;
  }
}

const styles = StyleSheet.create({
  safe: {
    flex: 1,
    backgroundColor: "#f3f7fb",
  },
  authContainer: {
    padding: 18,
    gap: 14,
  },
  title: {
    fontSize: 24,
    fontWeight: "700",
    color: "#0C3C64",
    textAlign: "center",
  },
  subtitle: {
    textAlign: "center",
    color: "#3f5263",
    marginBottom: 8,
  },
  header: {
    flexDirection: "row",
    alignItems: "center",
    gap: 10,
    padding: 12,
    backgroundColor: "#0C3C64",
  },
  headerTitle: {
    color: "#ffffff",
    fontSize: 16,
    fontWeight: "700",
  },
  headerSubtitle: {
    color: "#d2e5f8",
    fontSize: 12,
  },
  tabScroll: {
    maxHeight: 52,
    backgroundColor: "#e4eef8",
  },
  tabRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: 8,
    paddingHorizontal: 10,
    paddingVertical: 8,
  },
  tab: {
    paddingHorizontal: 12,
    paddingVertical: 8,
    borderRadius: 999,
    backgroundColor: "#d0e1f1",
  },
  tabActive: {
    backgroundColor: "#0C3C64",
  },
  tabText: {
    color: "#0C3C64",
    fontWeight: "600",
    fontSize: 12,
  },
  tabTextActive: {
    color: "#ffffff",
  },
  screen: {
    padding: 12,
    gap: 12,
  },
  card: {
    backgroundColor: "#ffffff",
    borderRadius: 14,
    borderWidth: 1,
    borderColor: "#d2e0ee",
    padding: 12,
    gap: 10,
  },
  cardTitle: {
    color: "#0C3C64",
    fontWeight: "700",
    fontSize: 17,
  },
  row: {
    flexDirection: "row",
    gap: 8,
    alignItems: "center",
    flexWrap: "wrap",
  },
  inputWrap: {
    gap: 6,
  },
  label: {
    color: "#0C3C64",
    fontWeight: "600",
    fontSize: 13,
  },
  input: {
    borderWidth: 1,
    borderColor: "#bfd3e6",
    borderRadius: 10,
    paddingHorizontal: 10,
    paddingVertical: 8,
    color: "#162636",
    backgroundColor: "#fcfdff",
  },
  inputMultiline: {
    minHeight: 72,
    textAlignVertical: "top",
  },
  primaryButton: {
    backgroundColor: "#0C3C64",
    borderRadius: 10,
    paddingHorizontal: 12,
    paddingVertical: 9,
  },
  primaryButtonText: {
    color: "#ffffff",
    fontWeight: "700",
  },
  secondaryButton: {
    backgroundColor: "#deebf7",
    borderRadius: 10,
    paddingHorizontal: 12,
    paddingVertical: 9,
  },
  secondaryButtonText: {
    color: "#0C3C64",
    fontWeight: "700",
  },
  summaryRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    backgroundColor: "#eff5fb",
    borderRadius: 10,
    paddingHorizontal: 10,
    paddingVertical: 8,
  },
  summaryLabel: {
    color: "#506273",
    fontSize: 13,
  },
  summaryValue: {
    color: "#0C3C64",
    fontWeight: "700",
    fontSize: 16,
  },
  listItem: {
    borderWidth: 1,
    borderColor: "#d7e4f0",
    backgroundColor: "#fbfdff",
    borderRadius: 10,
    padding: 10,
    gap: 6,
  },
  listTitle: {
    color: "#0C3C64",
    fontWeight: "700",
    fontSize: 13,
  },
  listSubtitle: {
    color: "#495d70",
    fontSize: 12,
  },
  loading: {
    color: "#0C3C64",
    fontWeight: "700",
    marginBottom: 8,
  },
  unread: {
    borderLeftWidth: 4,
    borderLeftColor: "#E7BE63",
  },
  pinned: {
    borderLeftWidth: 4,
    borderLeftColor: "#E7BE63",
  },
  modalBackdrop: {
    flex: 1,
    backgroundColor: "rgba(12, 21, 30, 0.45)",
    justifyContent: "center",
    alignItems: "center",
    padding: 18,
  },
  modalCard: {
    width: "100%",
    maxWidth: 420,
    borderRadius: 14,
    backgroundColor: "#ffffff",
    padding: 14,
    gap: 10,
  },
  demoCode: {
    fontWeight: "700",
    color: "#0C3C64",
    backgroundColor: "#edf3fa",
    padding: 8,
    borderRadius: 8,
  },
  segmentRow: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 8,
  },
  segment: {
    backgroundColor: "#e0ebf6",
    borderRadius: 999,
    paddingHorizontal: 10,
    paddingVertical: 7,
  },
  segmentActive: {
    backgroundColor: "#0C3C64",
  },
  segmentText: {
    color: "#0C3C64",
    fontSize: 12,
    fontWeight: "700",
  },
  segmentTextActive: {
    color: "#ffffff",
  },
  brandText: {
    marginTop: 8,
    fontSize: 24,
    color: "#0C3C64",
    fontWeight: "700",
  },
  brandSubText: {
    color: "#3f5263",
    fontSize: 12,
  },
});

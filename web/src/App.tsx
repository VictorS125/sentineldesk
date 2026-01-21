import { useEffect, useMemo, useState } from "react";
import {
  AuthenticatedTemplate,
  UnauthenticatedTemplate,
  useMsal,
} from "@azure/msal-react";
import { InteractionRequiredAuthError } from "@azure/msal-browser";
import { loginRequest } from "./authConfig";
import "./App.css";

const API_BASE = import.meta.env.VITE_API_BASE_URL as string;

interface Ticket {
  id: number;
  title: string;
  body: string;
  status: string;
  created_at?: string;
}

interface Comment {
  id: number;
  ticket_id: number;
  author_upn?: string;
  body: string;
  created_at?: string;
}

interface Alert {
  id: number;
  ts: string;
  rule_id: string;
  severity: string;
  context: string;
  triage_status: string;
  trigger_event_id?: number;
  ticket_id?: number;
}

interface Toast {
  id: number;
  message: string;
  type: "success" | "error" | "info";
}

async function callApi(path: string, accessToken: string, options?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      ...options?.headers,
    },
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

export default function App() {
  const { instance, accounts } = useMsal();
  const [activeTab, setActiveTab] = useState<"tickets" | "security" | "idor">("tickets");

  // Tickets state
  const [tickets, setTickets] = useState<Ticket[]>([]);
  const [selectedTicket, setSelectedTicket] = useState<Ticket | null>(null);
  const [comments, setComments] = useState<Comment[]>([]);
  const [newTitle, setNewTitle] = useState("");
  const [newBody, setNewBody] = useState("");
  const [newComment, setNewComment] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("");

  // Security state
  const [auditLog, setAuditLog] = useState<any[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [expandedAlert, setExpandedAlert] = useState<number | null>(null);
  const [highlightedEventId, setHighlightedEventId] = useState<number | null>(null);

  // IDOR demo state
  const [idorTicketId, setIdorTicketId] = useState("1");
  const [idorOutput, setIdorOutput] = useState<any>(null);

  // Loading states
  const [loadingTickets, setLoadingTickets] = useState(false);
  const [loadingComments, setLoadingComments] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  // Toast notifications
  const [toasts, setToasts] = useState<Toast[]>([]);
  let toastId = 0;

  const showToast = (message: string, type: "success" | "error" | "info" = "info") => {
    const id = ++toastId;
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 3000);
  };

  const account = useMemo(() => {
    return instance.getActiveAccount() ?? accounts[0] ?? null;
  }, [instance, accounts]);

  const signIn = async () => {
    await instance.loginRedirect(loginRequest);
  };

  const signOut = async () => {
    const active = instance.getActiveAccount() ?? accounts[0];
    await instance.logoutRedirect({ account: active });
  };

  const getToken = async () => {
    if (!account) throw new Error("No active account");
    try {
      const resp = await instance.acquireTokenSilent({
        ...loginRequest,
        account,
      });
      return resp.accessToken;
    } catch (e) {
      if (e instanceof InteractionRequiredAuthError) {
        const resp = await instance.acquireTokenPopup({
          ...loginRequest,
          account,
        });
        return resp.accessToken;
      }
      throw e;
    }
  };

  // Load tickets on mount
  useEffect(() => {
    if (account) {
      loadTickets();
    }
  }, [account, statusFilter]);

  // Scroll to highlighted audit event
  useEffect(() => {
    if (highlightedEventId && auditLog.length > 0) {
      // Small timeout to ensure DOM is ready
      setTimeout(() => {
        const el = document.getElementById(`audit-${highlightedEventId}`);
        if (el) {
          el.scrollIntoView({ behavior: "smooth", block: "center" });
        }
      }, 100);
    }
  }, [highlightedEventId, auditLog]);

  const loadTickets = async () => {
    setLoadingTickets(true);
    try {
      const token = await getToken();
      const path = statusFilter ? `/tickets?status=${statusFilter}` : "/tickets";
      const result = await callApi(path, token);
      if (result.ok) {
        setTickets(result.data.tickets || []);
      } else {
        showToast("Failed to load tickets", "error");
      }
    } catch (e) {
      showToast("Failed to load tickets", "error");
    } finally {
      setLoadingTickets(false);
    }
  };

  const loadComments = async (ticketId: number) => {
    setLoadingComments(true);
    try {
      const token = await getToken();
      const result = await callApi(`/tickets/${ticketId}/comments`, token);
      if (result.ok) {
        setComments(result.data || []);
      }
    } catch (e) {
      console.error("Failed to load comments", e);
    } finally {
      setLoadingComments(false);
    }
  };

  const createTicket = async () => {
    if (!newTitle.trim() || !newBody.trim()) {
      showToast("Title and description are required", "error");
      return;
    }
    setSubmitting(true);
    try {
      const token = await getToken();
      const result = await callApi("/tickets", token, {
        method: "POST",
        body: JSON.stringify({ title: newTitle.trim(), body: newBody.trim() }),
      });
      if (result.ok) {
        setNewTitle("");
        setNewBody("");
        showToast("Ticket created successfully!", "success");
        loadTickets();
      } else {
        showToast(result.data?.detail || "Failed to create ticket", "error");
      }
    } catch (e) {
      showToast("Failed to create ticket", "error");
    } finally {
      setSubmitting(false);
    }
  };

  const updateTicketStatus = async (ticketId: number, status: string) => {
    setSubmitting(true);
    try {
      const token = await getToken();
      const result = await callApi(`/tickets/${ticketId}`, token, {
        method: "PATCH",
        body: JSON.stringify({ status }),
      });
      if (result.ok) {
        showToast(`Status updated to ${status.replace("_", " ")}`, "success");
        loadTickets();
        if (selectedTicket?.id === ticketId) {
          setSelectedTicket({ ...selectedTicket, status });
        }
      } else {
        showToast("Failed to update status", "error");
      }
    } finally {
      setSubmitting(false);
    }
  };

  const deleteTicket = async (ticketId: number) => {
    if (!confirm("Are you sure you want to delete this ticket?")) return;
    setSubmitting(true);
    try {
      const token = await getToken();
      const result = await callApi(`/tickets/${ticketId}`, token, {
        method: "DELETE",
      });
      if (result.ok) {
        showToast("Ticket deleted", "success");
        setSelectedTicket(null);
        loadTickets();
      } else {
        showToast(result.data?.detail || "Failed to delete ticket", "error");
      }
    } finally {
      setSubmitting(false);
    }
  };

  const addComment = async () => {
    if (!selectedTicket || !newComment.trim()) return;
    setSubmitting(true);
    try {
      const token = await getToken();
      const result = await callApi(`/tickets/${selectedTicket.id}/comments`, token, {
        method: "POST",
        body: JSON.stringify({ body: newComment.trim() }),
      });
      if (result.ok) {
        setNewComment("");
        showToast("Comment added", "success");
        loadComments(selectedTicket.id);
      } else {
        showToast("Failed to add comment", "error");
      }
    } finally {
      setSubmitting(false);
    }
  };

  const selectTicket = async (ticket: Ticket) => {
    setSelectedTicket(ticket);
    loadComments(ticket.id);
  };

  const loadAudit = async () => {
    const token = await getToken();
    const result = await callApi("/admin/audit", token);
    if (result.ok) {
      setAuditLog(result.data.events || []);
    }
  };

  const loadAlerts = async () => {
    const token = await getToken();
    const result = await callApi("/admin/alerts", token);
    if (result.ok) {
      setAlerts(result.data.alerts || []);
    }
  };

  const escalateAlert = async (alertId: number) => {
    setSubmitting(true);
    try {
      const token = await getToken();
      const result = await callApi(`/admin/alerts/${alertId}/escalate`, token, { method: "POST" });
      if (result.ok) {
        showToast(`Alert escalated to Ticket #${result.data.ticket_id}`, "success");
        loadAlerts();
        loadTickets();
      } else {
        showToast("Failed to escalate alert", "error");
      }
    } finally {
      setSubmitting(false);
    }
  };

  const updateAlertStatus = async (alertId: number, status: string) => {
    // Optimistic update
    setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, triage_status: status } : a));

    const token = await getToken();
    callApi(`/admin/alerts/${alertId}`, token, {
      method: "PATCH",
      body: JSON.stringify({ status })
    });
  };

  // IDOR demo functions
  const testInsecure = async () => {
    setSubmitting(true);
    try {
      const token = await getToken();
      const result = await callApi(`/tickets/insecure/${idorTicketId}`, token);
      setIdorOutput({ endpoint: "🔓 INSECURE /tickets/insecure/" + idorTicketId, ...result });
      loadAudit();
      loadAlerts();
    } finally {
      setSubmitting(false);
    }
  };

  const testSecure = async () => {
    setSubmitting(true);
    try {
      const token = await getToken();
      const result = await callApi(`/tickets/${idorTicketId}`, token);
      setIdorOutput({ endpoint: "🔒 SECURE /tickets/" + idorTicketId, ...result });
      loadAudit();
      loadAlerts();
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div>
      {/* Toast notifications */}
      <div className="toast-container">
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast toast-${toast.type}`}>
            {toast.message}
          </div>
        ))}
      </div>

      <UnauthenticatedTemplate>
        <div className="login-screen">
          <h1>SentinelDesk</h1>
          <p>Secure ticket management with Microsoft Entra ID authentication</p>
          <button className="btn-primary" onClick={signIn}>
            Sign in with Microsoft
          </button>
        </div>
      </UnauthenticatedTemplate>

      <AuthenticatedTemplate>
        <header className="header">
          <div>
            <h1>SentinelDesk</h1>
            <p className="subtitle">Security-focused ticket management</p>
          </div>
          <div className="user-info">
            <span className="user-email">{account?.username}</span>
            <button className="btn-secondary btn-small" onClick={signOut}>
              Sign out
            </button>
          </div>
        </header>

        <div className="tabs">
          <button
            className={`tab ${activeTab === "tickets" ? "active" : ""}`}
            onClick={() => setActiveTab("tickets")}
          >
            Tickets
          </button>
          <button
            className={`tab ${activeTab === "security" ? "active" : ""}`}
            onClick={() => { setActiveTab("security"); loadAudit(); loadAlerts(); }}
          >
            Security
          </button>
          <button
            className={`tab ${activeTab === "idor" ? "active" : ""}`}
            onClick={() => setActiveTab("idor")}
          >
            IDOR Demo
          </button>
        </div>

        {activeTab === "tickets" && (
          <div className="grid">
            {/* Left column: Create & List */}
            <div>
              <div className="card">
                <h3 className="card-title">Create Ticket</h3>
                <div className="form-group">
                  <label className="form-label">Title</label>
                  <input
                    type="text"
                    placeholder="Enter ticket title..."
                    value={newTitle}
                    onChange={(e) => setNewTitle(e.target.value)}
                    disabled={submitting}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Description</label>
                  <textarea
                    placeholder="Describe the issue..."
                    value={newBody}
                    onChange={(e) => setNewBody(e.target.value)}
                    disabled={submitting}
                  />
                </div>
                <button className="btn-primary" onClick={createTicket} disabled={submitting}>
                  {submitting ? "Creating..." : "Create Ticket"}
                </button>
              </div>

              <div className="card">
                <div className="card-header">
                  <h3 className="card-title">Tickets</h3>
                  <select
                    value={statusFilter}
                    onChange={(e) => setStatusFilter(e.target.value)}
                    style={{ width: "auto" }}
                  >
                    <option value="">All</option>
                    <option value="open">Open</option>
                    <option value="in_progress">In Progress</option>
                    <option value="resolved">Resolved</option>
                  </select>
                </div>

                {loadingTickets ? (
                  <div className="empty-state">
                    <div className="spinner"></div>
                    Loading tickets...
                  </div>
                ) : tickets.length === 0 ? (
                  <div className="empty-state">No tickets found</div>
                ) : (
                  <div className="ticket-list">
                    {tickets.map((ticket) => (
                      <div
                        key={ticket.id}
                        className={`ticket-item ${selectedTicket?.id === ticket.id ? "selected" : ""}`}
                        onClick={() => selectTicket(ticket)}
                      >
                        <div className="ticket-item-content">
                          <div className="ticket-item-title">
                            #{ticket.id} {ticket.title}
                          </div>
                          <div className="ticket-item-meta">
                            {ticket.created_at
                              ? new Date(ticket.created_at).toLocaleDateString()
                              : ""}
                          </div>
                        </div>
                        <span className={`badge badge-${ticket.status}`}>
                          {ticket.status.replace("_", " ")}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Right column: Ticket detail */}
            <div>
              {selectedTicket ? (
                <div className="card">
                  <div className="card-header">
                    <h3 className="card-title">Ticket #{selectedTicket.id}</h3>
                    <div className="flex gap-2">
                      <span className={`badge badge-${selectedTicket.status}`}>
                        {selectedTicket.status.replace("_", " ")}
                      </span>
                      <button
                        className="btn-danger btn-small"
                        onClick={() => deleteTicket(selectedTicket.id)}
                        disabled={submitting}
                      >
                        Delete
                      </button>
                    </div>
                  </div>

                  <h4 style={{ marginTop: 0 }}>{selectedTicket.title}</h4>
                  <p style={{ color: "var(--text-secondary)" }}>{selectedTicket.body}</p>

                  <div className="form-group">
                    <label className="form-label">Update Status</label>
                    <div className="btn-group">
                      <button
                        className={`btn-small ${selectedTicket.status === "open" ? "btn-primary" : "btn-secondary"}`}
                        onClick={() => updateTicketStatus(selectedTicket.id, "open")}
                        disabled={submitting}
                      >
                        Open
                      </button>
                      <button
                        className={`btn-small ${selectedTicket.status === "in_progress" ? "btn-primary" : "btn-secondary"}`}
                        onClick={() => updateTicketStatus(selectedTicket.id, "in_progress")}
                        disabled={submitting}
                      >
                        In Progress
                      </button>
                      <button
                        className={`btn-small ${selectedTicket.status === "resolved" ? "btn-primary" : "btn-secondary"}`}
                        onClick={() => updateTicketStatus(selectedTicket.id, "resolved")}
                        disabled={submitting}
                      >
                        Resolved
                      </button>
                    </div>
                  </div>

                  <div className="section-title">Comments</div>

                  {loadingComments ? (
                    <div className="empty-state">Loading comments...</div>
                  ) : (
                    <div className="comment-list">
                      {comments.length === 0 ? (
                        <div className="empty-state">No comments yet</div>
                      ) : (
                        comments.map((comment) => (
                          <div key={comment.id} className="comment-item">
                            <div className="comment-author">{comment.author_upn || "Unknown"}</div>
                            <div className="comment-body">{comment.body}</div>
                          </div>
                        ))
                      )}
                    </div>
                  )}

                  <div className="form-group" style={{ marginTop: "1rem" }}>
                    <textarea
                      placeholder="Add a comment..."
                      value={newComment}
                      onChange={(e) => setNewComment(e.target.value)}
                      rows={2}
                      disabled={submitting}
                    />
                  </div>
                  <button className="btn-primary btn-small" onClick={addComment} disabled={submitting}>
                    {submitting ? "Adding..." : "Add Comment"}
                  </button>
                </div>
              ) : (
                <div className="card">
                  <div className="empty-state">
                    Select a ticket to view details
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === "security" && (
          <div className="grid">
            <div className="card">
              <div className="card-header">
                <h3 className="card-title">Security Alerts ({alerts.length})</h3>
                <div className="btn-group">
                  <button className="btn-secondary btn-small" onClick={loadAlerts}>
                    Refresh
                  </button>
                  <button
                    className="btn-primary btn-small"
                    onClick={async () => {
                      const token = await getToken();
                      const result = await callApi("/admin/simulate-attacks", token, { method: "POST" });
                      if (result.ok) {
                        showToast("Attack simulation started!", "success");
                        // Wait a moment for async detection logic
                        setTimeout(loadAlerts, 1000);
                        setTimeout(loadAudit, 1000);
                      }
                    }}
                  >
                    ⚡ Simulate Attacks
                  </button>
                  {alerts.length > 0 && (
                    <button
                      className="btn-danger btn-small"
                      onClick={async () => {
                        if (!confirm("Clear all alerts?")) return;
                        const token = await getToken();
                        const result = await callApi("/admin/alerts", token, { method: "DELETE" });
                        if (result.ok) {
                          showToast("All alerts cleared", "success");
                          loadAlerts();
                        }
                      }}
                    >
                      Clear All
                    </button>
                  )}
                </div>
              </div>
              {alerts.length === 0 ? (
                <div className="empty-state">No alerts</div>
              ) : (
                <div className="ticket-list">
                  {alerts.map((alert) => (
                    <div key={alert.id} className="alert-item">
                      <div
                        className="ticket-item"
                        onClick={() => setExpandedAlert(expandedAlert === alert.id ? null : alert.id)}
                        style={{ cursor: "pointer" }}
                      >
                        <div className="ticket-item-content">
                          <div className="ticket-item-title">
                            {expandedAlert === alert.id ? "▼" : "▶"} {alert.rule_id}
                          </div>
                          <div className="ticket-item-meta">
                            {new Date(alert.ts).toLocaleString()}
                          </div>
                        </div>
                        <div className="flex gap-2 items-center">
                          <span className={`badge badge-${alert.severity}`}>
                            {alert.severity}
                          </span>
                          <button
                            className="btn-danger btn-small"
                            onClick={async (e) => {
                              e.stopPropagation();
                              const token = await getToken();
                              const result = await callApi(`/admin/alerts/${alert.id}`, token, { method: "DELETE" });
                              if (result.ok) {
                                showToast("Alert dismissed", "success");
                                loadAlerts();
                              }
                            }}
                          >
                            ×
                          </button>
                        </div>
                      </div>
                      {expandedAlert === alert.id && (
                        <div className="alert-context">
                          <div className="alert-actions-bar">
                            <select
                              value={alert.triage_status || "new"}
                              onChange={(e) => updateAlertStatus(alert.id, e.target.value)}
                              className={`status-select status-${alert.triage_status || "new"}`}
                              onClick={(e) => e.stopPropagation()}
                            >
                              <option value="new">🔴 New</option>
                              <option value="investigating">🟡 Investigating</option>
                              <option value="resolved">🟢 Resolved</option>
                              <option value="false_positive">⚪ False Positive</option>
                            </select>

                            {alert.ticket_id ? (
                              <div className="linked-ticket">
                                🎫 Linked Ticket #{alert.ticket_id}
                              </div>
                            ) : (
                              <button
                                className="btn-primary btn-small"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  escalateAlert(alert.id);
                                }}
                                disabled={submitting}
                              >
                                🎫 Escalate to Incident
                              </button>
                            )}
                          </div>

                          <pre>{JSON.stringify(JSON.parse(alert.context), null, 2)}</pre>

                          <div className="flex gap-2" style={{ marginTop: "1rem" }}>
                            {alert.trigger_event_id && (
                              <button
                                className="btn-secondary btn-small"
                                style={{ margin: 0 }}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setHighlightedEventId(alert.trigger_event_id!);
                                  loadAudit();
                                  showToast(`Jumping to audit event #${alert.trigger_event_id}`, "info");
                                }}
                              >
                                View in Audit Log →
                              </button>
                            )}
                          </div>
                        </div>
                      )}

                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="card">
              <div className="card-header">
                <h3 className="card-title">Audit Log</h3>
                <div className="btn-group">
                  <button className="btn-secondary btn-small" onClick={loadAudit}>
                    Refresh
                  </button>
                  <button
                    className="btn-danger btn-small"
                    onClick={async () => {
                      if (!confirm("Clear entire audit log?")) return;
                      const token = await getToken();
                      const result = await callApi("/admin/audit", token, { method: "DELETE" });
                      if (result.ok) {
                        showToast("Audit log cleared", "success");
                        loadAudit();
                      }
                    }}
                  >
                    Clear Log
                  </button>
                  {highlightedEventId && (
                    <button
                      className="btn-secondary btn-small"
                      onClick={() => setHighlightedEventId(null)}
                    >
                      Clear Highlight
                    </button>
                  )}
                </div>
              </div>
              <div className="audit-list" style={{ maxHeight: "500px", overflowY: "auto" }}>
                {auditLog.slice(0, 50).map((event: any) => (
                  <div
                    key={event.id}
                    id={`audit-${event.id}`}
                    className={`audit-item ${highlightedEventId === event.id ? "highlighted" : ""}`}
                  >
                    <div className="audit-header">
                      <span className="audit-id">#{event.id}</span>
                      <span className={`badge badge-${event.result === "success" ? "resolved" : "open"}`}>
                        {event.result}
                      </span>
                    </div>
                    <div className="audit-action">{event.action}</div>
                    <div className="audit-meta">
                      {event.actor || "system"} • {event.target || "-"} • {new Date(event.ts).toLocaleString()}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )
        }

        {
          activeTab === "idor" && (
            <div>
              <div className="card">
                <h3 className="card-title">IDOR Vulnerability Demonstration</h3>
                <p style={{ color: "var(--text-secondary)", marginBottom: "1rem" }}>
                  This demonstrates the difference between a vulnerable and secure endpoint.
                  The <strong>insecure</strong> endpoint returns any ticket without authorization checks,
                  exposing sensitive data like <code>owner_sub</code>.
                </p>

                <div className="form-group" style={{ maxWidth: "200px" }}>
                  <label className="form-label">Ticket ID</label>
                  <input
                    type="number"
                    value={idorTicketId}
                    onChange={(e) => setIdorTicketId(e.target.value)}
                  />
                </div>

                <div className="btn-group">
                  <button className="btn-danger" onClick={testInsecure} disabled={submitting}>
                    {submitting ? "Loading..." : "🔓 GET Insecure (IDOR vulnerable)"}
                  </button>
                  <button className="btn-primary" onClick={testSecure} disabled={submitting}>
                    {submitting ? "Loading..." : "🔒 GET Secure (Protected)"}
                  </button>
                </div>
              </div>

              {idorOutput && (
                <div className="card">
                  <h3 className="card-title">{idorOutput.endpoint}</h3>
                  <div className="output-panel">
                    <pre>{JSON.stringify(idorOutput, null, 2)}</pre>
                  </div>
                </div>
              )}
            </div>
          )
        }
      </AuthenticatedTemplate >
    </div >
  );
}

import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  AlertTriangle, ArrowLeft, Boxes, CheckCircle2, Circle, Download, FileCode,
  Globe, LayoutGrid, Loader2, Network, ScrollText, Server, ShieldAlert,
  ShieldCheck, Trash2,
} from "lucide-react";
import { toast } from "sonner";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { isActive, ScanStatusBadge } from "@/components/ScanStatusBadge";
import { api, downloadFile, errorMessage } from "@/lib/api";
import { formatDate, LEVELS } from "@/lib/format";
import { countByCategory, healthScores, remediationActions, topHosts } from "@/lib/risk";
import { cn } from "@/lib/utils";

const POLL_MS = 5000;

const SEVERITY_TILES = [
  { key: "CRITICAL", label: "Critique", color: "#b91c1c" },
  { key: "HIGH", label: "Élevé", color: "#ea580c" },
  { key: "MEDIUM", label: "Moyen", color: "#ca8a04" },
  { key: "LOW", label: "Faible", color: "#15803d" },
];

// Health score 1..5 -> colour (1 = needs work, 5 = healthy).
const SCORE_COLOR = ["#b91c1c", "#b91c1c", "#ea580c", "#ca8a04", "#65a30d", "#15803d"];

const SEVERITY_CLASS = {
  CRITICAL: "bg-destructive text-destructive-foreground",
  HIGH: "bg-destructive/15 text-destructive",
  MEDIUM: "bg-warning/15 text-warning",
  LOW: "bg-secondary text-secondary-foreground",
  INFO: "bg-muted text-muted-foreground",
};
const SEVERITY_LABEL = {
  CRITICAL: "Critique", HIGH: "Élevé", MEDIUM: "Moyen", LOW: "Faible", INFO: "Info",
};
const SEVERITY_DOT = {
  CRITICAL: "#b91c1c", HIGH: "#ea580c", MEDIUM: "#ca8a04", LOW: "#15803d", INFO: "#6b7280",
};

// --- Left-sidebar menu (mirrors the Hexiosec layout) ---------------------------------------
const MENU = [
  { key: "overview", label: "Vue d'ensemble", icon: LayoutGrid },
  { group: "Gestion des risques", items: [
    { key: "actions", label: "Actions", icon: ScrollText },
    { key: "risks", label: "Risques", icon: ShieldAlert },
    { key: "health", label: "Santé", icon: ShieldCheck },
    { key: "metrics", label: "Métriques", icon: LayoutGrid },
  ] },
  { group: "Gestion des actifs", items: [
    { key: "domains", label: "Domaines", icon: Globe },
    { key: "ips", label: "Adresses IP", icon: Network },
    { key: "web", label: "Présence web", icon: Globe },
    { key: "services", label: "Services", icon: Server },
    { key: "certs", label: "Certificats", icon: ShieldCheck },
    { key: "components", label: "Composants", icon: Boxes },
  ] },
  { key: "reports", label: "Rapports", icon: Download },
];

// --- Small building blocks -----------------------------------------------------------------

function DiscoveryTile({ label, value }) {
  return (
    <div className="rounded-xl border bg-card p-4">
      <div className="text-2xl font-extrabold leading-none" style={{ fontFamily: "Manrope" }}>{value}</div>
      <div className="text-xs text-muted-foreground mt-1">{label}</div>
    </div>
  );
}

function SeverityCards({ counts }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      {SEVERITY_TILES.map(({ key, label, color }) => (
        <div key={key} className="rounded-xl p-4 text-white" style={{ backgroundColor: color }}>
          <div className="text-3xl font-extrabold leading-none">{counts?.[key] ?? 0}</div>
          <div className="text-xs uppercase tracking-wide opacity-95 mt-1">{label}</div>
        </div>
      ))}
    </div>
  );
}

function HealthPanel({ findings }) {
  const { categories, overall } = healthScores(findings);
  const perCat = countByCategory(findings);
  return (
    <div className="flex flex-col md:flex-row gap-6 items-center">
      <div className="flex flex-col items-center justify-center shrink-0">
        <div className="text-5xl font-extrabold" style={{ color: SCORE_COLOR[overall] }}>
          {overall}<span className="text-2xl text-muted-foreground font-bold">/5</span>
        </div>
        <div className="text-xs text-muted-foreground mt-1">Score global</div>
      </div>
      <div className="flex-1 w-full space-y-3">
        {categories.map(({ category, score }) => (
          <div key={category}>
            <div className="flex justify-between text-sm mb-1">
              <span>{category} <span className="text-muted-foreground">({perCat[category]})</span></span>
              <span className="tabular-nums font-medium" style={{ color: SCORE_COLOR[score] }}>{score}/5</span>
            </div>
            <div className="h-2 rounded bg-muted">
              <div className="h-full rounded" style={{ width: `${(score / 5) * 100}%`, backgroundColor: SCORE_COLOR[score] }} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function SeverityBadge({ severity }) {
  return (
    <Badge variant="outline" className={cn("border-transparent", SEVERITY_CLASS[severity])}>
      {SEVERITY_LABEL[severity] ?? severity}
    </Badge>
  );
}

function SectionCard({ title, description, children, count }) {
  return (
    <Card className="shadow-soft">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          {title}{count != null && <span className="text-sm font-normal text-muted-foreground">({count})</span>}
        </CardTitle>
        {description && <CardDescription>{description}</CardDescription>}
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

function Empty({ children }) {
  return <p className="text-sm text-muted-foreground">{children}</p>;
}

// --- Remediation actions (per-viewer "done" kept in localStorage) --------------------------

function useDoneSet(scanId) {
  const key = `sw-actions-done:${scanId}`;
  const [done, setDone] = useState(() => {
    try {
      const raw = localStorage.getItem(key);
      return new Set(raw ? JSON.parse(raw) : []);
    } catch {
      return new Set();
    }
  });
  const toggle = useCallback((id) => {
    setDone((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      try { localStorage.setItem(key, JSON.stringify([...next])); } catch { /* ignore */ }
      return next;
    });
  }, [key]);
  return [done, toggle];
}

function ActionRow({ action, isDone, onToggle }) {
  return (
    <button type="button" onClick={() => onToggle(action.id)}
            className={cn("w-full text-left flex gap-3 rounded-lg border p-3 transition hover:bg-muted/50",
                          isDone && "opacity-60")}>
      {isDone
        ? <CheckCircle2 className="h-5 w-5 shrink-0 text-green-600 mt-0.5" />
        : <Circle className="h-5 w-5 shrink-0 text-muted-foreground mt-0.5" />}
      <div className="space-y-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <SeverityBadge severity={action.severity} />
          <span className="text-xs text-muted-foreground">{action.category}</span>
          <span className="text-xs text-muted-foreground break-all">· {action.host}</span>
        </div>
        <div className={cn("text-sm font-medium", isDone && "line-through")}>{action.advice}</div>
        {action.description && <div className="text-xs text-muted-foreground">{action.description}</div>}
      </div>
    </button>
  );
}

function ActionsSection({ findings, scanId }) {
  const actions = remediationActions(findings);
  const [done, toggle] = useDoneSet(scanId);
  if (actions.length === 0) return <SectionCard title="Actions"><Empty>Aucune action.</Empty></SectionCard>;
  const todo = actions.filter((a) => !done.has(a.id));
  const handled = actions.filter((a) => done.has(a.id));
  return (
    <SectionCard title="Actions de remédiation"
      description={`${todo.length} à traiter · ${handled.length} traité(s). Coché = corrigé (enregistré sur cet appareil).`}>
      <div className="grid md:grid-cols-2 gap-6">
        <div className="space-y-2">
          <div className="text-sm font-semibold text-muted-foreground">À traiter ({todo.length})</div>
          {todo.length === 0 ? <Empty>Tout est traité 🎉</Empty>
            : todo.map((a) => <ActionRow key={a.id} action={a} isDone={false} onToggle={toggle} />)}
        </div>
        <div className="space-y-2">
          <div className="text-sm font-semibold text-muted-foreground">Traité ({handled.length})</div>
          {handled.length === 0 ? <Empty>Aucune action traitée.</Empty>
            : handled.map((a) => <ActionRow key={a.id} action={a} isDone onToggle={toggle} />)}
        </div>
      </div>
    </SectionCard>
  );
}

// --- Section: Overview ---------------------------------------------------------------------

function Overview({ report }) {
  const { summary } = report;
  const tiles = [
    ["Sous-domaines", summary.subdomains], ["Adresses IP", summary.ips],
    ["Services", summary.services ?? 0], ["Composants", summary.components ?? 0],
    ["URL", summary.urls], ["Certificats", summary.certificates ?? 0],
    ["Technologies", summary.technologies ?? 0], ["Risques", summary.findings],
  ];
  const checks = report.category_counts || {};
  return (
    <div className="space-y-6">
      <SectionCard title="Découverte">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {tiles.map(([label, value]) => <DiscoveryTile key={label} label={label} value={value} />)}
        </div>
      </SectionCard>

      {report.findings.length > 0 && (
        <div className="grid lg:grid-cols-2 gap-6">
          <SectionCard title="Risques par sévérité">
            <SeverityCards counts={report.severity_counts} />
          </SectionCard>
          <SectionCard title="Score de santé" description="Par catégorie (1 = à corriger, 5 = sain).">
            <HealthPanel findings={report.findings} />
          </SectionCard>
        </div>
      )}

      {Object.keys(checks).length > 0 && (
        <SectionCard title="Contrôles" description="Risques regroupés par type de contrôle.">
          <div className="space-y-2">
            {Object.entries(checks).map(([cat, n]) => (
              <div key={cat} className="flex items-center justify-between border-b py-2 last:border-0">
                <span className="text-sm">{cat}</span>
                <Badge variant="outline">{n}</Badge>
              </div>
            ))}
          </div>
        </SectionCard>
      )}
    </div>
  );
}

// --- Section: Risks ------------------------------------------------------------------------

function RisksSection({ report }) {
  if (report.findings.length === 0) return <SectionCard title="Risques"><Empty>Aucun risque détecté.</Empty></SectionCard>;
  return (
    <SectionCard title="Risques" count={report.findings.length}>
      <Table>
        <TableHeader>
          <TableRow><TableHead>Sévérité</TableHead><TableHead>Catégorie</TableHead><TableHead>Hôte</TableHead><TableHead>Description</TableHead></TableRow>
        </TableHeader>
        <TableBody>
          {report.findings.map((f, i) => (
            <TableRow key={i}>
              <TableCell><SeverityBadge severity={f.severity} /></TableCell>
              <TableCell className="text-muted-foreground text-xs whitespace-nowrap">{f.category || "—"}</TableCell>
              <TableCell className="break-all">{f.host}</TableCell>
              <TableCell>{f.description}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </SectionCard>
  );
}

// --- Section: Health (detail + top hosts) --------------------------------------------------

function HealthSection({ report }) {
  const hosts = topHosts(report.findings);
  return (
    <div className="space-y-6">
      <SectionCard title="Score de santé" description="Par catégorie (1 = à corriger, 5 = sain).">
        {report.findings.length ? <HealthPanel findings={report.findings} /> : <Empty>Aucun risque.</Empty>}
      </SectionCard>
      {hosts.length > 0 && (
        <SectionCard title="Top hôtes à risque" description="Les hôtes portant les risques les plus sévères, en premier.">
          <Table>
            <TableHeader>
              <TableRow><TableHead>Hôte</TableHead><TableHead className="text-right">Risques</TableHead><TableHead>Répartition</TableHead></TableRow>
            </TableHeader>
            <TableBody>
              {hosts.map((h) => (
                <TableRow key={h.host}>
                  <TableCell className="font-medium break-all">{h.host}</TableCell>
                  <TableCell className="text-right tabular-nums font-semibold">{h.total}</TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1.5">
                      {SEVERITY_TILES.map(({ key }) => h.counts[key] ? (
                        <span key={key} className="inline-flex items-center gap-1 text-xs tabular-nums" style={{ color: SEVERITY_DOT[key] }}>
                          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: SEVERITY_DOT[key] }} />{h.counts[key]}
                        </span>
                      ) : null)}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </SectionCard>
      )}
    </div>
  );
}

// --- Section: Metrics ----------------------------------------------------------------------

function MetricsSection({ report }) {
  const sev = report.severity_counts || {};
  const kev = report.components.filter((c) => c.vuln?.kev).length;
  const vulnComps = report.components.filter((c) => c.vuln).length;
  const metrics = [
    ["Risques au total", report.findings.length],
    ["Critiques", sev.CRITICAL ?? 0], ["Élevés", sev.HIGH ?? 0],
    ["Moyens", sev.MEDIUM ?? 0], ["Faibles", sev.LOW ?? 0],
    ["Composants vulnérables", vulnComps],
    ["Activement exploités (CISA KEV)", kev],
    ["Services exposés", report.services.length],
  ];
  return (
    <SectionCard title="Métriques">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {metrics.map(([label, value]) => <DiscoveryTile key={label} label={label} value={value} />)}
      </div>
    </SectionCard>
  );
}

// --- Section: assets -----------------------------------------------------------------------

function ipRows(subdomains) {
  const m = new Map();
  for (const s of subdomains) for (const ip of s.ips || []) {
    if (!m.has(ip)) m.set(ip, []);
    m.get(ip).push(s.host);
  }
  return [...m.entries()].map(([ip, hosts]) => ({ ip, hosts })).sort((a, b) => a.ip.localeCompare(b.ip));
}

function DomainsSection({ report }) {
  return (
    <SectionCard title="Domaines" count={report.subdomains.length}>
      {report.subdomains.length === 0 ? <Empty>Aucun sous-domaine.</Empty> : (
        <Table>
          <TableHeader><TableRow><TableHead>Hôte</TableHead><TableHead>IP</TableHead></TableRow></TableHeader>
          <TableBody>
            {report.subdomains.map((s) => (
              <TableRow key={s.host}>
                <TableCell className="font-medium break-all">{s.host}</TableCell>
                <TableCell className="text-muted-foreground">{s.ips.join(", ") || "—"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </SectionCard>
  );
}

function IpsSection({ report }) {
  const rows = ipRows(report.subdomains);
  return (
    <SectionCard title="Adresses IP" count={rows.length}>
      {rows.length === 0 ? <Empty>Aucune adresse IP.</Empty> : (
        <Table>
          <TableHeader><TableRow><TableHead>IP</TableHead><TableHead>Hôtes</TableHead></TableRow></TableHeader>
          <TableBody>
            {rows.map((r) => (
              <TableRow key={r.ip}>
                <TableCell className="font-mono">{r.ip}</TableCell>
                <TableCell className="text-muted-foreground break-all">{r.hosts.join(", ")}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </SectionCard>
  );
}

function WebSection({ report }) {
  return (
    <SectionCard title="Présence web" count={report.urls.length}>
      {report.urls.length === 0 ? <Empty>Aucune URL probée.</Empty> : (
        <ul className="space-y-1 text-sm">
          {report.urls.map((u) => <li key={u} className="break-all"><code>{u}</code></li>)}
        </ul>
      )}
    </SectionCard>
  );
}

function ServicesSection({ report }) {
  return (
    <SectionCard title="Services exposés" count={report.services.length}>
      {report.services.length === 0 ? <Empty>Aucun service exposé.</Empty> : (
        <Table>
          <TableHeader><TableRow><TableHead>Hôte</TableHead><TableHead>Port</TableHead><TableHead>Service</TableHead></TableRow></TableHeader>
          <TableBody>
            {report.services.map((s, i) => (
              <TableRow key={i}>
                <TableCell className="font-medium break-all">{s.host}</TableCell>
                <TableCell>{s.port}</TableCell>
                <TableCell className="text-muted-foreground">{s.protocol || "—"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </SectionCard>
  );
}

function CertsSection({ report }) {
  const certs = report.certificates || [];
  return (
    <SectionCard title="Certificats" count={certs.length}
      description="Certificats TLS observés sur les services web probés.">
      {certs.length === 0 ? (
        <Empty>Aucun certificat collecté (relancez un scan actif sur un domaine vérifié).</Empty>
      ) : (
        <Table>
          <TableHeader><TableRow><TableHead>Hôte</TableHead><TableHead>Sujet</TableHead><TableHead>Émetteur</TableHead><TableHead>Expire</TableHead></TableRow></TableHeader>
          <TableBody>
            {certs.map((c, i) => (
              <TableRow key={i}>
                <TableCell className="font-medium break-all">{c.host}</TableCell>
                <TableCell className="break-all">{c.subject || "—"}</TableCell>
                <TableCell className="text-muted-foreground break-all">{c.issuer || "—"}</TableCell>
                <TableCell className="text-muted-foreground whitespace-nowrap">{c.not_after || "—"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </SectionCard>
  );
}

function ComponentsSection({ report }) {
  return (
    <div className="space-y-6">
      <SectionCard title="Composants & versions" count={report.components.length}
        description="Versions déduites de ce que les hôtes annoncent (en-têtes, bannières, empreintes).">
        {report.components.length === 0 ? <Empty>Aucun composant détecté.</Empty> : (
          <Table>
            <TableHeader><TableRow><TableHead>Hôte</TableHead><TableHead>Composant</TableHead><TableHead>Version</TableHead><TableHead>Source</TableHead><TableHead>Vulnérable</TableHead></TableRow></TableHeader>
            <TableBody>
              {report.components.map((c, i) => (
                <TableRow key={i}>
                  <TableCell className="font-medium break-all">{c.host}</TableCell>
                  <TableCell>{c.product}</TableCell>
                  <TableCell className="font-mono text-sm">{c.version}</TableCell>
                  <TableCell className="text-muted-foreground text-xs">{c.source}</TableCell>
                  <TableCell>{c.vuln ? <SeverityBadge severity={c.vuln.severity} /> : <span className="text-muted-foreground">—</span>}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </SectionCard>
      {report.technologies.length > 0 && (
        <SectionCard title="Technologies détectées" count={report.technologies.length}>
          <Table>
            <TableHeader><TableRow><TableHead>Hôte</TableHead><TableHead>Technologie</TableHead></TableRow></TableHeader>
            <TableBody>
              {report.technologies.map((t, i) => (
                <TableRow key={i}>
                  <TableCell className="font-medium break-all">{t.host}</TableCell>
                  <TableCell className="text-muted-foreground break-all">{t.technology}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </SectionCard>
      )}
    </div>
  );
}

function ReportsSection({ scan, onDownload }) {
  return (
    <SectionCard title="Rapports" description="Exportez le rapport complet à partager.">
      <div className="flex flex-wrap gap-2">
        <Button onClick={() => onDownload("pdf")}><Download className="h-4 w-4" /> Télécharger le PDF</Button>
        <Button variant="outline" onClick={() => onDownload("html")}><FileCode className="h-4 w-4" /> Télécharger le HTML</Button>
      </div>
      {scan.level === "passive" && (
        <p className="text-xs text-muted-foreground mt-4">
          Scan passif : données issues de sources publiques uniquement, aucune requête n'a été
          envoyée vers vos systèmes.
        </p>
      )}
    </SectionCard>
  );
}

// --- Sidebar + section router --------------------------------------------------------------

function Sidebar({ section, setSection }) {
  const item = (it) => {
    const Icon = it.icon;
    return (
      <button key={it.key} type="button" onClick={() => setSection(it.key)}
        className={cn("w-full flex items-center gap-2 text-left px-3 py-2 rounded-md text-sm transition",
          section === it.key ? "bg-primary text-primary-foreground" : "hover:bg-muted text-foreground/80")}>
        {Icon && <Icon className="h-4 w-4 shrink-0" />}<span>{it.label}</span>
      </button>
    );
  };
  return (
    <nav className="space-y-1">
      {MENU.map((entry, i) => entry.group ? (
        <div key={i} className="pt-3">
          <div className="px-3 pb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">{entry.group}</div>
          {entry.items.map(item)}
        </div>
      ) : item(entry))}
    </nav>
  );
}

function ScanContent({ section, report, scan, scanId, onDownload }) {
  switch (section) {
    case "overview": return <Overview report={report} />;
    case "actions": return <ActionsSection findings={report.findings} scanId={scanId} />;
    case "risks": return <RisksSection report={report} />;
    case "health": return <HealthSection report={report} />;
    case "metrics": return <MetricsSection report={report} />;
    case "domains": return <DomainsSection report={report} />;
    case "ips": return <IpsSection report={report} />;
    case "web": return <WebSection report={report} />;
    case "services": return <ServicesSection report={report} />;
    case "certs": return <CertsSection report={report} />;
    case "components": return <ComponentsSection report={report} />;
    case "reports": return <ReportsSection scan={scan} onDownload={onDownload} />;
    default: return <Overview report={report} />;
  }
}

// --- Page ----------------------------------------------------------------------------------

export default function ScanDetail() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [report, setReport] = useState(null);
  const [notFound, setNotFound] = useState(false);
  const [section, setSection] = useState("overview");

  const load = useCallback(async () => {
    try {
      const res = await api.get(`/scans/${scanId}`);
      setScan(res.data);
      if (res.data.status === "done") {
        const rep = await api.get(`/scans/${scanId}/report`);
        setReport(rep.data);
      }
    } catch (err) {
      if (err.response?.status === 404) setNotFound(true);
      else toast.error(errorMessage(err));
    }
  }, [scanId]);

  useEffect(() => { load(); }, [load]);

  const active = scan && isActive(scan.status);
  useEffect(() => {
    if (!active) return undefined;
    const id = setInterval(load, POLL_MS);
    return () => clearInterval(id);
  }, [active, load]);

  const download = useCallback(async (ext) => {
    try {
      await downloadFile(`/scans/${scanId}/report.${ext}`, `surfaceattackwatch-${scan.domain}.${ext}`);
    } catch (err) {
      toast.error(ext === "pdf" ? "Export PDF indisponible pour le moment." : errorMessage(err));
    }
  }, [scanId, scan]);

  const remove = async () => {
    if (!window.confirm("Supprimer définitivement ce scan et son rapport ?")) return;
    try {
      await api.delete(`/scans/${scanId}`);
      toast.success("Scan supprimé.");
      navigate("/dashboard");
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  if (notFound) {
    return (
      <div className="text-center py-16 space-y-4">
        <p className="text-muted-foreground">Ce scan n'existe pas ou a expiré.</p>
        <Button asChild variant="outline"><Link to="/dashboard">Retour au tableau de bord</Link></Button>
      </div>
    );
  }
  if (!scan) {
    return <div className="flex justify-center py-16"><Loader2 className="h-8 w-8 animate-spin text-primary" /></div>;
  }

  return (
    <div className="space-y-6">
      <Link to="/dashboard" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-primary">
        <ArrowLeft className="h-4 w-4" /> Tableau de bord
      </Link>

      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold break-all">{scan.domain}</h1>
            <ScanStatusBadge status={scan.status} />
          </div>
          <p className="text-sm text-muted-foreground">
            Niveau {LEVELS[scan.level]?.label.toLowerCase() ?? scan.level} · lancé le {formatDate(scan.created_at)}
            {scan.finished_at && <> · terminé le {formatDate(scan.finished_at)}</>}
            {" "}· résultats supprimés le {formatDate(scan.expires_at)}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {scan.status === "done" && (
            <>
              <Button onClick={() => download("pdf")}><Download className="h-4 w-4" /> PDF</Button>
              <Button variant="outline" onClick={() => download("html")}><FileCode className="h-4 w-4" /> HTML</Button>
            </>
          )}
          {!active && (
            <Button variant="ghost" className="text-destructive hover:text-destructive" onClick={remove}>
              <Trash2 className="h-4 w-4" /> Supprimer
            </Button>
          )}
        </div>
      </div>

      {active && (
        <Card><CardContent className="py-12 flex flex-col items-center gap-3 text-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
          <p className="font-medium">{scan.status === "queued" ? "Scan en file d'attente…" : "Scan en cours…"}</p>
          <p className="text-sm text-muted-foreground">Cette page se met à jour automatiquement.</p>
        </CardContent></Card>
      )}

      {scan.status === "failed" && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Le scan a échoué</AlertTitle>
          <AlertDescription>
            <pre className="mt-2 whitespace-pre-wrap text-xs">{scan.error || "Erreur inconnue."}</pre>
          </AlertDescription>
        </Alert>
      )}

      {report && (
        <div className="flex flex-col md:flex-row gap-6">
          <aside className="md:w-56 shrink-0">
            <div className="md:sticky md:top-20"><Sidebar section={section} setSection={setSection} /></div>
          </aside>
          <div className="flex-1 min-w-0">
            <ScanContent section={section} report={report} scan={scan} scanId={scanId} onDownload={download} />
          </div>
        </div>
      )}
    </div>
  );
}

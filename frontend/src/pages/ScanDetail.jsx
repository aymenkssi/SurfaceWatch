import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { AlertTriangle, ArrowLeft, Download, FileCode, Loader2, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { isActive, ScanStatusBadge } from "@/components/ScanStatusBadge";
import { api, downloadFile, errorMessage } from "@/lib/api";
import { formatDate, LEVELS } from "@/lib/format";
import { countByCategory, healthScores } from "@/lib/risk";
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

const SEVERITY_CLASS = {
  CRITICAL: "bg-destructive text-destructive-foreground",
  HIGH: "bg-destructive/15 text-destructive",
  MEDIUM: "bg-warning/15 text-warning",
  LOW: "bg-secondary text-secondary-foreground",
  INFO: "bg-muted text-muted-foreground",
};

function Kpi({ label, value }) {
  return (
    <Card className="shadow-soft">
      <CardContent className="pt-6">
        <div className="text-3xl font-extrabold" style={{ fontFamily: "Manrope" }}>{value}</div>
        <div className="text-sm text-muted-foreground">{label}</div>
      </CardContent>
    </Card>
  );
}

function Report({ report }) {
  const { summary } = report;
  return (
    <div className="space-y-6">
      <div className="grid gap-4 grid-cols-2 md:grid-cols-4">
        <Kpi label="Sous-domaines" value={summary.subdomains} />
        <Kpi label="Adresses IP" value={summary.ips} />
        <Kpi label="URL" value={summary.urls} />
        <Kpi label="Services" value={summary.services ?? 0} />
        <Kpi label="Composants" value={summary.components ?? 0} />
        <Kpi label="Technologies" value={summary.technologies ?? 0} />
        <Kpi label="Vulnérabilités" value={summary.vulnerabilities ?? 0} />
        <Kpi label="Findings" value={summary.findings} />
      </div>

      {report.findings.length > 0 && (
        <div className="grid lg:grid-cols-2 gap-6">
          <Card className="shadow-soft">
            <CardHeader><CardTitle>Risques par sévérité</CardTitle></CardHeader>
            <CardContent><SeverityCards counts={summary.severity_counts} /></CardContent>
          </Card>
          <Card className="shadow-soft">
            <CardHeader>
              <CardTitle>Score de santé</CardTitle>
              <CardDescription>Par catégorie (1 = à corriger, 5 = sain).</CardDescription>
            </CardHeader>
            <CardContent><HealthPanel findings={report.findings} /></CardContent>
          </Card>
        </div>
      )}

      <Card className="shadow-soft">
        <CardHeader><CardTitle>Findings</CardTitle></CardHeader>
        <CardContent>
          {report.findings.length === 0 ? (
            <p className="text-sm text-muted-foreground">Aucun finding sur ce scan.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Sévérité</TableHead>
                  <TableHead>Hôte</TableHead>
                  <TableHead>Description</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {report.findings.map((f, i) => (
                  <TableRow key={i}>
                    <TableCell>
                      <Badge variant="outline" className={cn("border-transparent", SEVERITY_CLASS[f.severity])}>
                        {f.severity}
                      </Badge>
                    </TableCell>
                    <TableCell className="break-all">{f.host}</TableCell>
                    <TableCell>{f.description}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {report.services?.length > 0 && (
        <Card className="shadow-soft">
          <CardHeader><CardTitle>Services exposés</CardTitle></CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow><TableHead>Hôte</TableHead><TableHead>Port</TableHead><TableHead>Service</TableHead></TableRow>
              </TableHeader>
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
          </CardContent>
        </Card>
      )}

      {report.components?.length > 0 && (
        <Card className="shadow-soft">
          <CardHeader>
            <CardTitle>Composants &amp; versions</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Hôte</TableHead><TableHead>Composant</TableHead>
                  <TableHead>Version</TableHead><TableHead>Source</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {report.components.map((c, i) => (
                  <TableRow key={i}>
                    <TableCell className="font-medium break-all">{c.host}</TableCell>
                    <TableCell>{c.product}</TableCell>
                    <TableCell className="font-mono text-sm">{c.version}</TableCell>
                    <TableCell className="text-muted-foreground text-xs">{c.source}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <p className="text-xs text-muted-foreground">
              Versions déduites de ce que les hôtes annoncent (en-têtes HTTP, bannières de
              service). Les vulnérabilités correspondantes (CVE / CISA KEV) apparaissent dans
              les findings ci-dessus. Un correctif rétroporté peut rendre un verdict inexact.
            </p>
          </CardContent>
        </Card>
      )}

      {report.technologies?.length > 0 && (
        <Card className="shadow-soft">
          <CardHeader><CardTitle>Technologies détectées</CardTitle></CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow><TableHead>Hôte</TableHead><TableHead>Technologie / version</TableHead></TableRow>
              </TableHeader>
              <TableBody>
                {report.technologies.map((t, i) => (
                  <TableRow key={i}>
                    <TableCell className="font-medium break-all">{t.host}</TableCell>
                    <TableCell className="text-muted-foreground break-all">{t.technology}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <Card className="shadow-soft">
        <CardHeader><CardTitle>Sous-domaines découverts</CardTitle></CardHeader>
        <CardContent>
          {report.subdomains.length === 0 ? (
            <p className="text-sm text-muted-foreground">Aucun sous-domaine découvert.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow><TableHead>Hôte</TableHead><TableHead>IP</TableHead></TableRow>
              </TableHeader>
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
        </CardContent>
      </Card>

      {report.urls.length > 0 && (
        <Card className="shadow-soft">
          <CardHeader><CardTitle>Services web</CardTitle></CardHeader>
          <CardContent>
            <ul className="space-y-1 text-sm">
              {report.urls.map((u) => <li key={u} className="break-all"><code>{u}</code></li>)}
            </ul>
          </CardContent>
        </Card>
      )}

      {report.level === "passive" && (
        <p className="text-xs text-muted-foreground">
          Scan passif : données issues de sources publiques uniquement, aucune requête n'a été
          envoyée vers vos systèmes. Ce rapport est un instantané et peut être incomplet.
        </p>
      )}
    </div>
  );
}

export default function ScanDetail() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [report, setReport] = useState(null);
  const [notFound, setNotFound] = useState(false);

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

  const download = async (ext) => {
    try {
      await downloadFile(`/scans/${scanId}/report.${ext}`, `surfaceattackwatch-${scan.domain}.${ext}`);
    } catch (err) {
      toast.error(ext === "pdf" ? "Export PDF indisponible pour le moment." : errorMessage(err));
    }
  };

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

      {report && <Report report={report} />}
    </div>
  );
}

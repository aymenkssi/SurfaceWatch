import { useCallback, useEffect, useState } from "react";
import { CheckCircle2, Clock, Loader2, Mail, RefreshCw, Search, ShieldCheck, Undo2 } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ScanStatusBadge } from "@/components/ScanStatusBadge";
import { SmtpSettingsCard } from "@/components/SmtpSettingsCard";
import { api, errorMessage } from "@/lib/api";
import { formatDate } from "@/lib/format";

const LEVEL_LABELS = { passive: "Passif", standard: "Standard", advanced: "Avancé" };
const STATUS_LABELS = { queued: "En file", running: "En cours", done: "Terminés", failed: "Échecs" };
const ACTION_LABELS = {
  "scan.requested": "Scan demandé",
  "domain.manual_verify": "Validation manuelle",
  "domain.revoke_verify": "Vérification retirée",
  "smtp.update": "Config. e-mail modifiée",
  "smtp.reset": "Config. e-mail supprimée",
  "smtp.test": "E-mail de test",
};
const DOMAIN_FILTERS = { pending: "Non vérifiés", verified: "Vérifiés", all: "Tous" };

const formatDuration = (seconds) => {
  if (seconds == null) return "—";
  if (seconds < 60) return `${seconds} s`;
  return `${Math.round(seconds / 60)} min`;
};

function StatTile({ label, value, hint }) {
  return (
    <Card className="shadow-soft">
      <CardContent className="p-4">
        <p className="text-xs text-muted-foreground">{label}</p>
        <p className="text-2xl font-bold tabular-nums">{value}</p>
        {hint && <p className="text-xs text-muted-foreground mt-1">{hint}</p>}
      </CardContent>
    </Card>
  );
}

// Single-series bar chart: scans requested per day (last 30 days).
function ScansPerDayChart({ data }) {
  const [hover, setHover] = useState(null);
  const max = Math.max(1, ...data.map((d) => d.count));
  const label = (iso) => new Date(`${iso}T00:00:00`).toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit" });
  const shown = hover ?? data[data.length - 1];

  return (
    <div>
      <p className="text-sm text-muted-foreground mb-2 h-5">
        {shown && <><span className="text-foreground font-medium">{label(shown.date)}</span> · {shown.count} scan(s)</>}
      </p>
      <div className="flex items-end h-40 gap-[2px] border-b" onMouseLeave={() => setHover(null)}>
        {data.map((d) => (
          <div key={d.date} className="flex-1 h-full flex items-end cursor-default"
            onMouseEnter={() => setHover(d)} aria-label={`${label(d.date)} : ${d.count}`}>
            <div className={`w-full rounded-t-[4px] ${hover?.date === d.date ? "bg-primary" : "bg-primary/70"}`}
              style={{ height: d.count ? `${Math.max(2, (d.count / max) * 100)}%` : 0 }} />
          </div>
        ))}
      </div>
      <div className="flex justify-between text-xs text-muted-foreground mt-1">
        <span>{data.length ? label(data[0].date) : ""}</span>
        <span>{data.length ? label(data[data.length - 1].date) : ""}</span>
      </div>
    </div>
  );
}

function Breakdown({ title, counts, labels }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  return (
    <div>
      <p className="text-sm font-medium mb-2">{title}</p>
      <div className="space-y-2">
        {Object.keys(labels).map((key) => {
          const n = counts[key] ?? 0;
          return (
            <div key={key} className="text-sm">
              <div className="flex justify-between"><span>{labels[key]}</span><span className="tabular-nums">{n}</span></div>
              <div className="h-1.5 rounded bg-muted mt-1">
                <div className="h-full rounded bg-primary/70" style={{ width: total ? `${(n / total) * 100}%` : 0 }} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function DomainRow({ domain, onChange }) {
  const [reason, setReason] = useState("");
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  const call = async (fn, success) => {
    setBusy(true);
    try {
      await fn();
      toast.success(success);
      setOpen(false);
      setReason("");
      onChange();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const verify = (e) => {
    e.preventDefault();
    call(() => api.post(`/admin/domains/${domain.id}/verify`, { reason }),
         `${domain.name} validé manuellement.`);
  };

  const revoke = () => {
    if (!window.confirm(`Retirer la vérification de ${domain.name} ? Le propriétaire devra le revérifier.`)) return;
    call(() => api.post(`/admin/domains/${domain.id}/revoke`), `Vérification de ${domain.name} retirée.`);
  };

  return (
    <TableRow>
      <TableCell className="font-medium break-all">{domain.name}</TableCell>
      <TableCell className="break-all">{domain.owner_email}</TableCell>
      <TableCell>
        {domain.verified ? (
          <Badge variant="outline" className="border-transparent bg-success/15 text-success gap-1">
            <CheckCircle2 className="h-3 w-3" />
            {domain.verification_method === "manual" ? "Manuel" : "DNS"}
          </Badge>
        ) : (
          <Badge variant="outline" className="border-transparent bg-warning/15 text-warning gap-1">
            <Clock className="h-3 w-3" /> {domain.token_expired ? "Jeton expiré" : "En attente"}
          </Badge>
        )}
      </TableCell>
      <TableCell>{formatDate(domain.verified ? domain.verified_at : domain.created_at)}</TableCell>
      <TableCell className="text-right">
        {domain.verified ? (
          <Button size="sm" variant="ghost" onClick={revoke} disabled={busy}>
            <Undo2 className="h-4 w-4" /> Retirer
          </Button>
        ) : open ? (
          <form onSubmit={verify} className="flex gap-2 justify-end">
            <Input autoFocus value={reason} onChange={(e) => setReason(e.target.value)}
              placeholder="Motif (obligatoire, journalisé)" className="h-8 w-56" minLength={5} maxLength={500} required />
            <Button size="sm" type="submit" disabled={busy || reason.trim().length < 5}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : "Valider"}
            </Button>
            <Button size="sm" type="button" variant="ghost" onClick={() => setOpen(false)}>Annuler</Button>
          </form>
        ) : (
          <Button size="sm" variant="outline" onClick={() => setOpen(true)}>
            <ShieldCheck className="h-4 w-4" /> Valider manuellement
          </Button>
        )}
      </TableCell>
    </TableRow>
  );
}

export default function Admin() {
  const [stats, setStats] = useState(null);
  const [active, setActive] = useState([]);
  const [audit, setAudit] = useState([]);
  const [domains, setDomains] = useState([]);
  const [filter, setFilter] = useState("pending");
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState(""); // applied on submit, not on every keystroke
  const [loading, setLoading] = useState(true);

  const loadDomains = useCallback(async () => {
    const res = await api.get("/admin/domains", { params: { status_filter: filter, q: query } });
    setDomains(res.data);
  }, [filter, query]);

  const load = useCallback(async () => {
    try {
      const [s, a, l] = await Promise.all([
        api.get("/admin/stats"), api.get("/admin/scans"), api.get("/admin/audit"), loadDomains(),
      ]);
      setStats(s.data);
      setActive(a.data);
      setAudit(l.data);
    } catch (err) {
      toast.error(errorMessage(err, "Impossible de charger les statistiques."));
    } finally {
      setLoading(false);
    }
  }, [loadDomains]);

  useEffect(() => { load(); }, [load]);

  if (loading) {
    return <div className="flex justify-center py-16"><Loader2 className="h-8 w-8 animate-spin text-primary" /></div>;
  }
  if (!stats) return null;
  const { users, domains: d, scans } = stats;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Administration</h1>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" asChild>
            <a href="#smtp"><Mail className="h-4 w-4" /> Configuration e-mail</a>
          </Button>
          <Button variant="outline" size="sm" onClick={load}><RefreshCw className="h-4 w-4" /> Actualiser</Button>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatTile label="Utilisateurs" value={users.total} hint={`+${users.new_7d} sur 7 j · +${users.new_30d} sur 30 j`} />
        <StatTile label="Domaines vérifiés" value={d.verified_dns + d.verified_manual}
          hint={`${d.verified_dns} DNS · ${d.verified_manual} manuels · ${d.pending} en attente`} />
        <StatTile label="Scans demandés (24 h)" value={scans.requested_24h}
          hint={`${scans.requested_7d} sur 7 j · ${scans.requested_total} au total`} />
        <StatTile label="Scans en cours" value={scans.active} hint={`${users.with_verified_domain} utilisateur(s) avec domaine vérifié`} />
      </div>

      <SmtpSettingsCard />

      <div className="grid lg:grid-cols-3 gap-4">
        <Card className="shadow-soft lg:col-span-2">
          <CardHeader><CardTitle className="text-base">Scans demandés par jour (30 jours)</CardTitle></CardHeader>
          <CardContent><ScansPerDayChart data={scans.per_day} /></CardContent>
        </Card>
        <Card className="shadow-soft">
          <CardHeader><CardTitle className="text-base">Répartition</CardTitle></CardHeader>
          <CardContent className="space-y-6">
            <Breakdown title="Par niveau (historique)" counts={scans.by_level} labels={LEVEL_LABELS} />
            <Breakdown title={`Par statut (${stats.retention_days} derniers jours)`} counts={scans.by_status} labels={STATUS_LABELS} />
            <div className="text-sm space-y-1">
              <p className="font-medium">Durée moyenne</p>
              {Object.keys(LEVEL_LABELS).map((lvl) => (
                <p key={lvl} className="flex justify-between">
                  <span>{LEVEL_LABELS[lvl]}</span>
                  <span className="tabular-nums">{formatDuration(scans.avg_duration_seconds[lvl])}</span>
                </p>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card className="shadow-soft">
        <CardHeader>
          <CardTitle className="text-base">Domaines</CardTitle>
          <CardDescription>
            La validation manuelle remplace la preuve DNS TXT : ne l'utilisez qu'après avoir confirmé la
            propriété par un autre moyen. Chaque validation est journalisée avec son motif.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <form className="flex flex-wrap gap-2" onSubmit={(e) => { e.preventDefault(); setQuery(search.trim()); }}>
            <div className="relative flex-1 min-w-[200px]">
              <Search className="h-4 w-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
              <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Domaine ou e-mail" className="pl-9" />
            </div>
            {Object.entries(DOMAIN_FILTERS).map(([key, text]) => (
              <Button key={key} type="button" size="sm" variant={filter === key ? "default" : "outline"}
                onClick={() => setFilter(key)}>{text}</Button>
            ))}
          </form>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Domaine</TableHead><TableHead>Propriétaire</TableHead>
                  <TableHead>Statut</TableHead><TableHead>Date</TableHead><TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {domains.length === 0 ? (
                  <TableRow><TableCell colSpan={5} className="text-center text-muted-foreground">Aucun domaine.</TableCell></TableRow>
                ) : domains.map((dom) => <DomainRow key={dom.id} domain={dom} onChange={load} />)}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      <Card className="shadow-soft">
        <CardHeader><CardTitle className="text-base">Scans en cours</CardTitle></CardHeader>
        <CardContent className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Domaine</TableHead><TableHead>Utilisateur</TableHead><TableHead>Niveau</TableHead>
                <TableHead>Statut</TableHead><TableHead>Demandé le</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {active.length === 0 ? (
                <TableRow><TableCell colSpan={5} className="text-center text-muted-foreground">Aucun scan en cours.</TableCell></TableRow>
              ) : active.map((s) => (
                <TableRow key={s.id}>
                  <TableCell className="font-medium">{s.domain}</TableCell>
                  <TableCell>{s.user_email}</TableCell>
                  <TableCell>{LEVEL_LABELS[s.level] ?? s.level}</TableCell>
                  <TableCell><ScanStatusBadge status={s.status} /></TableCell>
                  <TableCell>{formatDate(s.created_at)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card className="shadow-soft">
        <CardHeader><CardTitle className="text-base">Journal d'audit (50 derniers)</CardTitle></CardHeader>
        <CardContent className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Date</TableHead><TableHead>Action</TableHead><TableHead>Par</TableHead>
                <TableHead>Domaine</TableHead><TableHead>Niveau</TableHead><TableHead>IP</TableHead><TableHead>Détails</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {audit.map((a) => (
                <TableRow key={a.id}>
                  <TableCell className="whitespace-nowrap">{formatDate(a.created_at)}</TableCell>
                  <TableCell>{ACTION_LABELS[a.action] ?? a.action}</TableCell>
                  <TableCell className="break-all">{a.user_email}</TableCell>
                  <TableCell>{a.domain}</TableCell>
                  <TableCell>{a.level ? `${LEVEL_LABELS[a.level] ?? a.level}${a.consent ? " (consenti)" : ""}` : "—"}</TableCell>
                  <TableCell>{a.source_ip ?? "—"}</TableCell>
                  <TableCell className="text-xs text-muted-foreground max-w-xs break-words">{a.details ?? ""}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

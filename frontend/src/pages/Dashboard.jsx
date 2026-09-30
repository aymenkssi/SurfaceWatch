import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Loader2, Plus } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { DomainCard } from "@/components/DomainCard";
import { isActive, ScanStatusBadge } from "@/components/ScanStatusBadge";
import { api, errorMessage } from "@/lib/api";
import { formatDate, LEVELS } from "@/lib/format";

const POLL_MS = 5000;

export default function Dashboard() {
  const navigate = useNavigate();
  const [domains, setDomains] = useState([]);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [newDomain, setNewDomain] = useState("");
  const [adding, setAdding] = useState(false);
  const [starting, setStarting] = useState(false);

  const load = useCallback(async () => {
    try {
      const [d, s] = await Promise.all([api.get("/domains"), api.get("/scans")]);
      setDomains(d.data);
      setScans(s.data);
    } catch (err) {
      toast.error(errorMessage(err, "Impossible de charger vos données."));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const hasActiveScan = scans.some((s) => isActive(s.status));
  useEffect(() => {
    if (!hasActiveScan) return undefined;
    const id = setInterval(load, POLL_MS);
    return () => clearInterval(id);
  }, [hasActiveScan, load]);

  const addDomain = async (e) => {
    e.preventDefault();
    setAdding(true);
    try {
      await api.post("/domains", { domain: newDomain });
      setNewDomain("");
      await load();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setAdding(false);
    }
  };

  const startScan = async (domain, level) => {
    setStarting(true);
    try {
      const res = await api.post("/scans", { domain_id: domain.id, level });
      toast.success(`Scan ${LEVELS[level].label.toLowerCase()} de ${domain.name} lancé.`);
      navigate(`/scans/${res.data.id}`);
    } catch (err) {
      toast.error(errorMessage(err));
      load();
    } finally {
      setStarting(false);
    }
  };

  if (loading) {
    return <div className="flex justify-center py-16"><Loader2 className="h-8 w-8 animate-spin text-primary" /></div>;
  }

  return (
    <div className="space-y-10">
      <section className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold">Mes domaines</h1>
            <p className="text-sm text-muted-foreground">
              Le scan passif est ouvert à tout domaine ajouté. Le scan standard exige une preuve de propriété.
            </p>
          </div>
          <form onSubmit={addDomain} className="flex gap-2 w-full sm:w-auto">
            <Input placeholder="exemple.fr" value={newDomain} required maxLength={300}
                   onChange={(e) => setNewDomain(e.target.value)} className="sm:w-64" />
            <Button type="submit" disabled={adding}>
              {adding ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
              Ajouter
            </Button>
          </form>
        </div>

        {domains.length === 0 ? (
          <Card><CardContent className="py-10 text-center text-muted-foreground">
            Ajoutez un premier domaine pour commencer.
          </CardContent></Card>
        ) : (
          <div className="grid gap-4 md:grid-cols-2">
            {domains.map((d) => (
              <DomainCard key={d.id} domain={d} onChange={load} onScan={startScan}
                          scanBusy={starting || hasActiveScan} />
            ))}
          </div>
        )}
      </section>

      <section>
        <Card className="shadow-soft">
          <CardHeader>
            <CardTitle>Historique des scans</CardTitle>
          </CardHeader>
          <CardContent>
            {scans.length === 0 ? (
              <p className="text-sm text-muted-foreground">Aucun scan pour l'instant.</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Domaine</TableHead>
                    <TableHead>Niveau</TableHead>
                    <TableHead>Statut</TableHead>
                    <TableHead className="hidden sm:table-cell">Lancé le</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {scans.map((s) => (
                    <TableRow key={s.id}>
                      <TableCell className="font-medium break-all">{s.domain}</TableCell>
                      <TableCell>{LEVELS[s.level]?.label ?? s.level}</TableCell>
                      <TableCell><ScanStatusBadge status={s.status} /></TableCell>
                      <TableCell className="hidden sm:table-cell">{formatDate(s.created_at)}</TableCell>
                      <TableCell className="text-right">
                        <Button asChild variant="link" size="sm"><Link to={`/scans/${s.id}`}>Voir</Link></Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </section>
    </div>
  );
}

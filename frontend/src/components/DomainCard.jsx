import { useState } from "react";
import { CheckCircle2, Clock, Loader2, RefreshCw, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CopyField } from "@/components/CopyField";
import { api, errorMessage } from "@/lib/api";
import { formatDate, LEVELS } from "@/lib/format";

function verifyErrorMessage({ verify_error, verify_found = [], record_name, name }) {
  const prefix = record_name.slice(0, -(name.length + 1));
  switch (verify_error) {
    case "doubled_name":
      return `L'enregistrement a été créé à ${record_name}.${name} : votre fournisseur DNS ajoute déjà le domaine. Saisissez seulement « ${prefix} » comme nom.`;
    case "mismatch":
      return `Un enregistrement TXT existe mais sa valeur ne correspond pas au jeton actuel (trouvé : ${verify_found.join(", ")}). Copiez la valeur affichée ci-dessous.`;
    default:
      return "Enregistrement TXT introuvable sur les serveurs DNS du domaine. Vérifiez le nom et le type (TXT) de l'enregistrement, puis réessayez dans quelques minutes.";
  }
}

export function DomainCard({ domain, onChange, onScan, scanBusy }) {
  const [busy, setBusy] = useState(null);

  const run = async (action, fn) => {
    setBusy(action);
    try {
      await fn();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(null);
    }
  };

  const verify = () => run("verify", async () => {
    const res = await api.post(`/domains/${domain.id}/verify`);
    if (res.data.verified) toast.success(`${domain.name} est vérifié.`);
    else toast.warning(verifyErrorMessage(res.data), { duration: 10000 });
    onChange();
  });

  const regenerate = () => run("regenerate", async () => {
    await api.post("/domains", { domain: domain.name, renew: true });
    toast.success("Nouveau jeton généré. Mettez à jour votre enregistrement TXT.");
    onChange();
  });

  const remove = () => {
    if (!window.confirm(`Supprimer ${domain.name} ?`)) return;
    run("delete", async () => {
      await api.delete(`/domains/${domain.id}`);
      onChange();
    });
  };

  return (
    <Card className="shadow-soft">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-3">
        <CardTitle className="text-lg break-all">{domain.name}</CardTitle>
        {domain.verified ? (
          <Badge variant="outline" className="border-transparent bg-success/15 text-success gap-1">
            <CheckCircle2 className="h-3 w-3" />
            {domain.verification_method === "manual" ? "Vérifié (manuel)" : "Vérifié"}
          </Badge>
        ) : (
          <Badge variant="outline" className="border-transparent bg-warning/15 text-warning gap-1">
            <Clock className="h-3 w-3" /> Non vérifié
          </Badge>
        )}
      </CardHeader>
      <CardContent className="space-y-4">
        {!domain.verified && (
          <div className="space-y-3 rounded-lg border bg-muted/40 p-3">
            <p className="text-sm">
              Créez cet enregistrement <strong>TXT</strong> dans la zone DNS du domaine :
            </p>
            <CopyField label="Nom" value={domain.record_name} />
            <CopyField label="Valeur" value={domain.record_value} />
            <p className="text-xs text-muted-foreground">
              {domain.token_expired
                ? "Ce jeton a expiré."
                : `Jeton valable jusqu'au ${formatDate(domain.token_expires_at)}.`}
            </p>
            <div className="flex flex-wrap gap-2">
              {domain.token_expired ? (
                <Button size="sm" onClick={regenerate} disabled={!!busy}>
                  {busy === "regenerate" ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
                  Nouveau jeton
                </Button>
              ) : (
                <Button size="sm" onClick={verify} disabled={!!busy}>
                  {busy === "verify" && <Loader2 className="h-4 w-4 animate-spin" />}
                  Vérifier
                </Button>
              )}
            </div>
          </div>
        )}

        <div className="flex flex-wrap items-center gap-2">
          {Object.entries(LEVELS).map(([level, { label, description, requiresConsent }]) => {
            const locked = level !== "passive" && !domain.verified;
            const run = () => {
              if (requiresConsent && !window.confirm(
                `Le niveau « ${label} » lance un scan actif vers ${domain.name}. ` +
                "Vous confirmez être autorisé à scanner ce domaine ?")) return;
              onScan(domain, level, !!requiresConsent);
            };
            return (
              <Button key={level} size="sm" variant={level === "passive" ? "secondary" : "default"}
                      disabled={locked || scanBusy} title={description} onClick={run}>
                Scan {label.toLowerCase()}
              </Button>
            );
          })}
          <Button size="sm" variant="ghost" className="ml-auto text-destructive hover:text-destructive"
                  onClick={remove} disabled={!!busy} aria-label={`Supprimer ${domain.name}`}>
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

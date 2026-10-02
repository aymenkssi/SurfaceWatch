import { useCallback, useEffect, useState } from "react";
import { Loader2, Mail, RotateCcw, Send } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, errorMessage } from "@/lib/api";
import { formatDate } from "@/lib/format";

const SECURITY_LABELS = { starttls: "STARTTLS (587)", ssl: "SSL/TLS (465)", none: "Aucune" };
const SOURCE_LABELS = { admin: "Configuré ici", env: "Repli sur le .env", none: "Non configuré" };

// Form values from the API response. With nothing configured, start from Brevo's relay.
function toForm(data) {
  const brevo = data.brevo_defaults;
  const empty = data.source === "none";
  return {
    host: empty ? brevo.host : data.host,
    port: empty ? brevo.port : data.port,
    security: empty ? brevo.security : data.security,
    username: data.username ?? "",
    password: "",
    clear_password: false,
    from_address: data.from_address ?? "",
    public_url: data.public_url ?? "",
  };
}

function Field({ id, label, hint, children }) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      {children}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

export function SmtpSettingsCard() {
  const [data, setData] = useState(null);
  const [form, setForm] = useState(null);
  const [testTo, setTestTo] = useState("");
  const [busy, setBusy] = useState(null); // "save" | "test" | "reset"
  const [loadError, setLoadError] = useState(null);

  const apply = (d) => { setData(d); setForm(toForm(d)); };

  const load = useCallback(async () => {
    setLoadError(null);
    try {
      apply((await api.get("/admin/smtp")).data);
    } catch (err) {
      setLoadError(errorMessage(err, "Impossible de charger la configuration e-mail."));
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Always show the card, even while loading or when the API call fails, so it can be found.
  if (!form) {
    return (
      <Card id="smtp" className="shadow-soft scroll-mt-20">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Mail className="h-4 w-4" /> Configuration e-mail (SMTP)
          </CardTitle>
          {loadError && <CardDescription className="text-destructive">{loadError}</CardDescription>}
        </CardHeader>
        <CardContent>
          {loadError ? (
            <Button variant="outline" size="sm" onClick={load}>
              <RotateCcw className="h-4 w-4" /> Réessayer
            </Button>
          ) : (
            <Loader2 className="h-5 w-5 animate-spin text-primary" />
          )}
        </CardContent>
      </Card>
    );
  }
  const set = (key) => (e) => setForm({ ...form, [key]: e.target.value });

  const run = async (kind, fn) => {
    setBusy(kind);
    try {
      await fn();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(null);
    }
  };

  const save = (e) => {
    e.preventDefault();
    run("save", async () => {
      const body = { ...form, port: Number(form.port), password: form.password || null };
      apply((await api.put("/admin/smtp", body)).data);
      toast.success("Configuration e-mail enregistrée.");
    });
  };

  const sendTest = () => run("test", async () => {
    const res = await api.post("/admin/smtp/test", { to: testTo.trim() || null });
    toast.success(`E-mail de test envoyé à ${res.data.sent_to}.`);
  });

  const reset = () => {
    if (!window.confirm("Supprimer la configuration enregistrée ici ? Les variables SMTP du .env s'appliqueront à nouveau.")) return;
    run("reset", async () => {
      apply((await api.delete("/admin/smtp")).data);
      toast.success("Configuration supprimée.");
    });
  };

  const useBrevo = () => setForm({ ...form, ...data.brevo_defaults });
  const passwordHint = data.password_unreadable
    ? "La clé enregistrée n'est plus lisible (SECRET_KEY modifiée) : saisissez-la à nouveau."
    : data.password_set
      ? "Une clé est enregistrée (chiffrée, jamais réaffichée). Laissez vide pour la conserver."
      : "Pour Brevo : la clé SMTP (onglet « SMTP & API » › SMTP), pas la clé API.";

  return (
    <Card id="smtp" className="shadow-soft scroll-mt-20">
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <CardTitle className="text-base flex items-center gap-2"><Mail className="h-4 w-4" /> E-mails (SMTP)</CardTitle>
          <Badge variant="outline" className={data.enabled
            ? "border-transparent bg-success/15 text-success" : "border-transparent bg-warning/15 text-warning"}>
            {SOURCE_LABELS[data.source]}{data.enabled ? "" : " · e-mails désactivés"}
          </Badge>
        </div>
        <CardDescription>
          Mot de passe oublié et notifications de fin de scan. Pré-rempli pour le relais Brevo,
          mais tout fournisseur SMTP convient. Cette configuration prime sur les variables SMTP du .env.
          {data.updated_at && <> Modifiée le {formatDate(data.updated_at)} par {data.updated_by}.</>}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <form onSubmit={save} className="grid sm:grid-cols-2 gap-4">
          <Field id="smtp-host" label="Serveur SMTP">
            <Input id="smtp-host" value={form.host} onChange={set("host")} required maxLength={253} />
          </Field>
          <div className="grid grid-cols-2 gap-4">
            <Field id="smtp-port" label="Port">
              <Input id="smtp-port" type="number" min={1} max={65535} value={form.port} onChange={set("port")} required />
            </Field>
            <Field id="smtp-security" label="Sécurité">
              <select id="smtp-security" value={form.security} onChange={set("security")}
                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm">
                {Object.entries(SECURITY_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
            </Field>
          </div>
          <Field id="smtp-user" label="Identifiant" hint="Pour Brevo : l'identifiant SMTP affiché dans « SMTP & API ».">
            <Input id="smtp-user" value={form.username} onChange={set("username")} autoComplete="off" maxLength={254} />
          </Field>
          <Field id="smtp-password" label="Mot de passe / clé SMTP" hint={passwordHint}>
            <Input id="smtp-password" type="password" value={form.password} onChange={set("password")}
              autoComplete="new-password" maxLength={500} disabled={form.clear_password}
              placeholder={data.password_set ? "•••••••• (configurée)" : ""} />
            {data.password_set && (
              <label className="flex items-center gap-2 text-xs text-muted-foreground">
                <input type="checkbox" checked={form.clear_password}
                  onChange={(e) => setForm({ ...form, clear_password: e.target.checked, password: "" })} />
                Supprimer la clé enregistrée
              </label>
            )}
          </Field>
          <Field id="smtp-from" label="Expéditeur" hint="Adresse d'un domaine authentifié chez le fournisseur (SPF/DKIM).">
            <Input id="smtp-from" type="email" value={form.from_address} onChange={set("from_address")}
              placeholder="noreply@surfaceattackwatch.com" required />
          </Field>
          <Field id="smtp-url" label="URL publique (liens des e-mails)"
            hint={`Vide = valeur du .env (${data.default_public_url}).`}>
            <Input id="smtp-url" type="url" value={form.public_url} onChange={set("public_url")}
              placeholder="https://surfaceattackwatch.com" maxLength={300} />
          </Field>
          <div className="sm:col-span-2 flex flex-wrap gap-2">
            <Button type="submit" disabled={busy !== null}>
              {busy === "save" && <Loader2 className="h-4 w-4 animate-spin" />} Enregistrer
            </Button>
            <Button type="button" variant="outline" onClick={useBrevo}>Valeurs Brevo</Button>
            {data.source === "admin" && (
              <Button type="button" variant="ghost" onClick={reset} disabled={busy !== null}>
                <RotateCcw className="h-4 w-4" /> Revenir au .env
              </Button>
            )}
          </div>
        </form>

        <div className="border-t pt-4 space-y-2">
          <p className="text-sm font-medium">Envoyer un e-mail de test</p>
          <p className="text-xs text-muted-foreground">Utilise la configuration enregistrée (enregistrez d'abord vos modifications).</p>
          <div className="flex flex-wrap gap-2">
            <Input type="email" value={testTo} onChange={(e) => setTestTo(e.target.value)}
              placeholder="Destinataire (par défaut : votre adresse)" className="flex-1 min-w-[220px]" />
            <Button type="button" variant="outline" onClick={sendTest} disabled={busy !== null || !data.enabled}>
              {busy === "test" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />} Envoyer
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

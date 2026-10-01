import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { KeyRound, Loader2, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/context/AuthContext";
import { api, errorMessage } from "@/lib/api";
import { formatDate } from "@/lib/format";

function NotificationsCard() {
  const { user, setUser } = useAuth();
  const [emailEnabled, setEmailEnabled] = useState(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api.get("/features").then((res) => setEmailEnabled(res.data.email)).catch(() => setEmailEnabled(false));
  }, []);

  const toggle = async (checked) => {
    const previous = user;
    setUser({ ...user, notify_scan_done: checked });
    setSaving(true);
    try {
      const res = await api.patch("/users/me", { notify_scan_done: checked });
      setUser(res.data);
      toast.success(checked ? "Notifications activées." : "Notifications désactivées.");
    } catch (err) {
      setUser(previous);
      toast.error(errorMessage(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card className="shadow-soft">
      <CardHeader>
        <CardTitle>Notifications par e-mail</CardTitle>
        <CardDescription>
          Les e-mails contiennent seulement un lien : le rapport reste accessible après connexion.
          {emailEnabled === false &&
            " L'envoi d'e-mails n'est pas encore activé sur ce serveur : votre choix est enregistré et s'appliquera dès son activation."}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <label className="flex items-center gap-3 text-sm cursor-pointer">
          <input type="checkbox" className="h-4 w-4 accent-primary"
                 checked={!!user.notify_scan_done} disabled={saving}
                 onChange={(e) => toggle(e.target.checked)} />
          M'avertir quand un scan est terminé ou a échoué
        </label>
      </CardContent>
    </Card>
  );
}

function PasswordCard() {
  const { user } = useAuth();
  const [sending, setSending] = useState(false);
  const [sent, setSent] = useState(false);

  const sendResetLink = async () => {
    setSending(true);
    try {
      await api.post("/auth/forgot-password", { email: user.email });
      setSent(true);
      toast.success(`Lien de réinitialisation envoyé à ${user.email}.`);
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setSending(false);
    }
  };

  return (
    <Card className="shadow-soft">
      <CardHeader>
        <CardTitle>Mot de passe</CardTitle>
        <CardDescription>
          Recevez par e-mail un lien pour choisir un nouveau mot de passe (valable une heure,
          utilisable une fois). Vos sessions ouvertes seront fermées après le changement.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        <Button variant="outline" onClick={sendResetLink} disabled={sending}>
          {sending ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
          M'envoyer un lien de réinitialisation
        </Button>
        {sent && (
          <p className="text-sm text-muted-foreground">
            E-mail envoyé à {user.email}. Pensez à vérifier vos spams.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

function DeleteAccountCard() {
  const { logout } = useAuth();
  const navigate = useNavigate();
  const [confirming, setConfirming] = useState(false);
  const [password, setPassword] = useState("");
  const [deleting, setDeleting] = useState(false);

  const deleteAccount = async (e) => {
    e.preventDefault();
    setDeleting(true);
    try {
      await api.delete("/users/me", { data: { password } });
      logout();
      toast.success("Votre compte et toutes vos données ont été supprimés.");
      navigate("/");
    } catch (err) {
      toast.error(errorMessage(err));
      setDeleting(false);
    }
  };

  return (
    <Card className="border-destructive/40">
      <CardHeader>
        <CardTitle>Supprimer mon compte</CardTitle>
        <CardDescription>
          Supprime définitivement votre compte, vos domaines et vos résultats de scan. Seul le
          journal légal des scans demandés (e-mail, domaine, niveau, IP, date) est conservé.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {!confirming ? (
          <Button variant="destructive" onClick={() => setConfirming(true)}>
            <Trash2 className="h-4 w-4" />
            Supprimer mon compte
          </Button>
        ) : (
          <form onSubmit={deleteAccount} className="space-y-4 max-w-sm">
            <div className="space-y-2">
              <Label htmlFor="delete-password">Confirmez avec votre mot de passe</Label>
              <Input id="delete-password" type="password" required autoComplete="current-password"
                     autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
              <p className="text-xs text-muted-foreground">Cette action est irréversible.</p>
            </div>
            <div className="flex gap-2">
              <Button type="submit" variant="destructive" disabled={deleting || !password}>
                {deleting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
                Supprimer définitivement
              </Button>
              <Button type="button" variant="ghost" disabled={deleting}
                      onClick={() => { setConfirming(false); setPassword(""); }}>
                Annuler
              </Button>
            </div>
          </form>
        )}
      </CardContent>
    </Card>
  );
}

export default function Account() {
  const { user } = useAuth();

  return (
    <div className="max-w-2xl space-y-6">
      <h1 className="text-2xl font-bold">Mon compte</h1>
      <Card className="shadow-soft">
        <CardHeader><CardTitle>Profil</CardTitle></CardHeader>
        <CardContent className="text-sm space-y-1">
          <p><span className="text-muted-foreground">E-mail :</span> {user.email}</p>
          <p><span className="text-muted-foreground">Inscrit le :</span> {formatDate(user.created_at)}</p>
        </CardContent>
      </Card>
      <PasswordCard />
      <NotificationsCard />
      <DeleteAccountCard />
    </div>
  );
}

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Loader2, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/context/AuthContext";
import { api, errorMessage } from "@/lib/api";
import { formatDate } from "@/lib/format";

export default function Account() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [deleting, setDeleting] = useState(false);

  const deleteAccount = async () => {
    if (!window.confirm("Supprimer votre compte, vos domaines et tous vos rapports ? Cette action est définitive.")) return;
    setDeleting(true);
    try {
      await api.delete("/users/me");
      logout();
      toast.success("Votre compte a été supprimé.");
      navigate("/");
    } catch (err) {
      toast.error(errorMessage(err));
      setDeleting(false);
    }
  };

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
      <Card className="border-destructive/40">
        <CardHeader>
          <CardTitle>Supprimer mon compte</CardTitle>
          <CardDescription>
            Supprime votre compte, vos domaines et vos résultats de scan. Le journal des scans
            demandés est conservé pour des raisons légales.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button variant="destructive" onClick={deleteAccount} disabled={deleting}>
            {deleting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
            Supprimer définitivement
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

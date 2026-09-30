import { Link } from "react-router-dom";
import { FileText, Globe, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { useAuth } from "@/context/AuthContext";

const STEPS = [
  {
    icon: ShieldCheck,
    title: "1. Prouvez la propriété",
    text: "Ajoutez votre domaine et publiez un enregistrement DNS TXT unique. Aucun scan actif sans cette preuve.",
  },
  {
    icon: Globe,
    title: "2. Lancez un scan",
    text: "Mode passif (sources publiques) ou standard (actif léger). Les réglages de scan sont fixés côté serveur.",
  },
  {
    icon: FileText,
    title: "3. Lisez le rapport",
    text: "Sous-domaines, adresses IP, services web et findings triés par sévérité. Export PDF.",
  },
];

export default function Home() {
  const { isAuthenticated } = useAuth();
  return (
    <div className="space-y-16">
      <section className="text-center pt-8 space-y-6">
        <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight text-balance">
          Cartographiez votre surface d'attaque externe
        </h1>
        <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
          SurfaceWatch découvre gratuitement les actifs exposés de votre domaine et
          vous remet un rapport clair des risques à traiter en priorité.
        </p>
        <div className="flex gap-3 justify-center">
          <Button asChild size="lg">
            <Link to={isAuthenticated ? "/dashboard" : "/register"}>
              {isAuthenticated ? "Aller au tableau de bord" : "Commencer gratuitement"}
            </Link>
          </Button>
        </div>
      </section>

      <section className="grid gap-4 md:grid-cols-3">
        {STEPS.map(({ icon: Icon, title, text }) => (
          <Card key={title} className="shadow-soft">
            <CardContent className="pt-6 space-y-3">
              <Icon className="h-8 w-8 text-accent" />
              <h3 className="font-bold">{title}</h3>
              <p className="text-sm text-muted-foreground">{text}</p>
            </CardContent>
          </Card>
        ))}
      </section>

      <section className="rounded-xl border bg-card p-6 text-sm text-muted-foreground space-y-2">
        <h2 className="text-base font-bold text-foreground">Vos données</h2>
        <p>
          Hébergement dans l'Union européenne. Les résultats de scan sont supprimés
          automatiquement après 30 jours, et vous pouvez supprimer votre compte à tout moment.
        </p>
      </section>
    </div>
  );
}

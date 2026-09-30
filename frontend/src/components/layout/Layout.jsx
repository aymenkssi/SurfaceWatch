import { Link, NavLink, Outlet, useNavigate } from "react-router-dom";
import { LogOut, Radar, User } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/context/AuthContext";
import { cn } from "@/lib/utils";

function Navbar() {
  const { isAuthenticated, logout } = useAuth();
  const navigate = useNavigate();
  const linkClass = ({ isActive }) =>
    cn("text-sm font-medium transition-colors hover:text-primary",
       isActive ? "text-primary" : "text-muted-foreground");

  return (
    <header className="border-b bg-card/80 backdrop-blur sticky top-0 z-40">
      <div className="mx-auto max-w-6xl px-4 h-16 flex items-center justify-between">
        <Link to="/" className="flex items-center gap-2 font-bold text-lg" style={{ fontFamily: "Manrope" }}>
          <Radar className="h-6 w-6 text-accent" />
          SurfaceWatch
        </Link>
        <nav className="flex items-center gap-4">
          {isAuthenticated ? (
            <>
              <NavLink to="/dashboard" className={linkClass}>Tableau de bord</NavLink>
              <NavLink to="/account" className={linkClass} aria-label="Mon compte">
                <User className="h-4 w-4" />
              </NavLink>
              <Button variant="ghost" size="sm" onClick={() => { logout(); navigate("/"); }}>
                <LogOut className="h-4 w-4" />
                <span className="hidden sm:inline">Déconnexion</span>
              </Button>
            </>
          ) : (
            <>
              <NavLink to="/login" className={linkClass}>Connexion</NavLink>
              <Button asChild size="sm"><Link to="/register">Créer un compte</Link></Button>
            </>
          )}
        </nav>
      </div>
    </header>
  );
}

function Footer() {
  return (
    <footer className="border-t mt-16">
      <div className="mx-auto max-w-6xl px-4 py-6 text-xs text-muted-foreground flex flex-col sm:flex-row gap-2 justify-between">
        <span>SurfaceWatch · logiciel libre sous licence AGPL-3.0 · moteur de scan : BBOT</span>
        <span>Ne scannez que des domaines qui vous appartiennent.</span>
      </div>
    </footer>
  );
}

export function Layout() {
  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <main className="flex-1 mx-auto w-full max-w-6xl px-4 py-8">
        <Outlet />
      </main>
      <Footer />
    </div>
  );
}

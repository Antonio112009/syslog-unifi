"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Activity, LockKeyhole, LogIn, Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export default function LoginPage() {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const res = await fetch("/api/auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      });

      if (res.ok) {
        router.push("/");
        router.refresh();
      } else {
        setError("Invalid password");
      }
    } catch {
      setError("Connection failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="relative grid min-h-dvh place-items-center overflow-hidden p-4 sm:p-8">
      <div
        className="pointer-events-none absolute inset-0 opacity-70"
        aria-hidden="true"
      >
        <div className="absolute -left-24 top-16 size-80 rounded-full bg-primary/10 blur-3xl" />
        <div className="absolute -right-20 bottom-8 size-96 rounded-full bg-muted-foreground/10 blur-3xl" />
      </div>

      <div className="relative grid w-full max-w-4xl items-center gap-12 lg:grid-cols-[1.1fr_0.9fr]">
        <section className="hidden flex-col gap-6 lg:flex">
          <div className="flex size-12 items-center justify-center rounded-2xl bg-primary text-primary-foreground shadow-lg shadow-primary/20">
            <Activity className="size-6" />
          </div>
          <div className="flex flex-col gap-3">
            <p className="font-mono text-xs uppercase tracking-[0.2em] text-primary">
              Private observability console
            </p>
            <h1 className="max-w-lg text-4xl font-semibold leading-tight tracking-tight">
              See what your network is saying, as it happens.
            </h1>
            <p className="max-w-md text-base leading-relaxed text-muted-foreground">
              Search, filter, and inspect live UniFi events from one focused workspace.
            </p>
          </div>
          <div className="flex items-center gap-2 font-mono text-xs text-muted-foreground">
            <span className="size-2 rounded-full bg-status-online" />
            Real-time stream with local retention
          </div>
        </section>

        <Card className="w-full max-w-md justify-self-end bg-card/85 shadow-2xl backdrop-blur-xl">
          <CardHeader>
            <div className="mb-3 flex size-11 items-center justify-center rounded-xl bg-primary/10 text-primary lg:hidden">
              <Shield className="size-5" />
            </div>
            <CardTitle className="text-xl">UniFi Syslog Console</CardTitle>
            <CardDescription>
              Sign in to open the live monitoring workspace.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="flex flex-col gap-4">
              <div className="flex flex-col gap-1.5">
                <label htmlFor="password" className="text-sm font-medium">
                  Password
                </label>
                <Input
                  id="password"
                  type="password"
                  placeholder="Enter your password"
                  value={password}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                    setPassword(e.target.value)
                  }
                  aria-invalid={Boolean(error)}
                  autoFocus
                  autoComplete="current-password"
                />
              </div>
              {error && (
                <p className="text-sm text-destructive" role="alert" aria-live="polite">
                  {error}
                </p>
              )}
              <Button type="submit" className="w-full" disabled={loading || !password}>
                {loading ? (
                  <LockKeyhole className="animate-pulse" data-icon="inline-start" />
                ) : (
                  <LogIn data-icon="inline-start" />
                )}
                {loading ? "Signing in..." : "Sign in"}
              </Button>
            </form>
          </CardContent>
          <CardFooter className="text-xs text-muted-foreground">
            Credentials are validated by this server and are not stored in the browser.
          </CardFooter>
        </Card>
      </div>
    </main>
  );
}

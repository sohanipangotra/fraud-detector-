import { motion } from 'framer-motion';
import { ShieldCheck, Activity, Cpu, Lock, Sparkles, Terminal } from 'lucide-react';

export function Header() {
  return (
    <header className="relative pt-10 pb-8 overflow-hidden">
      {/* Background Glows */}
      <div className="absolute inset-0 bg-gradient-to-b from-primary/10 via-transparent to-transparent pointer-events-none" />
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[700px] h-[280px] bg-primary/10 rounded-full blur-[140px] pointer-events-none" />

      <div className="relative max-w-5xl mx-auto px-6 text-center">
        {/* SOC Live Pill */}
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-secondary/80 border border-primary/30 text-xs font-mono mb-6 backdrop-blur-md"
        >
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-primary" />
          </span>
          <span className="text-primary font-semibold tracking-wider">THREAT TELEMETRY: ACTIVE</span>
          <span className="text-muted-foreground/60">•</span>
          <span className="text-muted-foreground">SOC v2.4 ENTERPRISE ENGINE</span>
        </motion.div>

        {/* Title */}
        <motion.h1
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="text-4xl sm:text-5xl md:text-6xl font-bold tracking-tight mb-4"
        >
          <span className="gradient-text-cyber tracking-wider">FRAUDGUARD</span>
          <span className="text-foreground"> AI</span>
        </motion.h1>

        {/* Subtitle */}
        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="text-muted-foreground text-base sm:text-lg max-w-2xl mx-auto mb-8 font-sans"
        >
          Next-generation financial crime, wire diversion, and spearphishing detection powered by neural embeddings and multi-vector threat heuristics.
        </motion.p>

        {/* Feature Capabilities */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="flex flex-wrap justify-center items-center gap-2.5 sm:gap-3"
        >
          <div className="flex items-center gap-2 px-3.5 py-1.5 bg-card/80 border border-primary/20 rounded-lg backdrop-blur-sm">
            <ShieldCheck className="w-3.5 h-3.5 text-primary" />
            <span className="text-xs font-mono text-muted-foreground">BEC & Wire Fraud</span>
          </div>

          <div className="flex items-center gap-2 px-3.5 py-1.5 bg-card/80 border border-primary/20 rounded-lg backdrop-blur-sm">
            <Cpu className="w-3.5 h-3.5 text-warning" />
            <span className="text-xs font-mono text-muted-foreground">Local Neural Engine</span>
          </div>

          <div className="flex items-center gap-2 px-3.5 py-1.5 bg-card/80 border border-primary/20 rounded-lg backdrop-blur-sm">
            <Activity className="w-3.5 h-3.5 text-accent" />
            <span className="text-xs font-mono text-muted-foreground">IOC Forensics</span>
          </div>

          <div className="flex items-center gap-2 px-3.5 py-1.5 bg-card/80 border border-primary/20 rounded-lg backdrop-blur-sm">
            <Terminal className="w-3.5 h-3.5 text-success" />
            <span className="text-xs font-mono text-muted-foreground">MITRE ATT&CK Mapped</span>
          </div>

          <div className="flex items-center gap-2 px-3.5 py-1.5 bg-card/80 border border-primary/20 rounded-lg backdrop-blur-sm">
            <Lock className="w-3.5 h-3.5 text-primary" />
            <span className="text-xs font-mono text-muted-foreground">Zero-Trust Privacy</span>
          </div>
        </motion.div>
      </div>
    </header>
  );
}

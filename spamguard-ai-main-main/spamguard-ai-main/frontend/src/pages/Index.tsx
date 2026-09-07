import { Header } from '@/components/Header';
import { FraudDetector } from '@/components/FraudDetector';

const Index = () => {
  return (
    <div className="min-h-screen bg-background relative overflow-hidden">
      {/* Background Grid */}
      <div 
        className="absolute inset-0 opacity-[0.02]"
        style={{
          backgroundImage: `
            linear-gradient(to right, hsl(165 100% 50%) 1px, transparent 1px),
            linear-gradient(to bottom, hsl(165 100% 50%) 1px, transparent 1px)
          `,
          backgroundSize: '60px 60px',
        }}
      />
      
      {/* Gradient Orbs */}
      <div className="absolute top-20 right-10 w-72 h-72 bg-accent/10 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute bottom-20 left-10 w-96 h-96 bg-primary/10 rounded-full blur-[150px] pointer-events-none" />
      
      <div className="relative z-10">
        <Header />
        
        <main className="px-6 pb-16">
          <FraudDetector />
        </main>

        {/* Footer */}
        <footer className="border-t border-primary/10 py-8 mt-12 bg-card/30 backdrop-blur-sm">
          <div className="max-w-5xl mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
              <p className="text-xs font-mono text-muted-foreground">
                FRAUDGUARD AI v2.4 • Enterprise Fraud Intelligence & Threat Defense
              </p>
            </div>
            <p className="text-xs font-mono text-muted-foreground/80">
              MITRE ATT&CK Aligned • Zero Data Retention • Local Neural Model
            </p>
          </div>
        </footer>
      </div>
    </div>
  );
};

export default Index;

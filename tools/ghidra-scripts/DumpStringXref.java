// DumpStringXref.java — find defined strings containing <substr>, and decompile
// every function that references them (i.e. "which function does X?"). Great for
// locating the USB I/O layer from log strings like "WinUsb_WritePipe".
//   -postScript DumpStringXref.java <outdir> <substr1> [substr2] ...
// @category verimark
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class DumpStringXref extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) { println("usage: DumpStringXref <outdir> <substr>..."); return; }
        File outdir = new File(args[0]); outdir.mkdirs();
        List<String> subs = new ArrayList<>();
        for (int i = 1; i < args.length; i++) subs.add(args[i].toLowerCase());

        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();

        Set<Function> hits = new LinkedHashSet<>();
        DataIterator di = currentProgram.getListing().getDefinedData(true);
        while (di.hasNext() && !monitor.isCancelled()) {
            Data d = di.next();
            Object v = (d == null) ? null : d.getValue();
            if (!(v instanceof String)) continue;
            String s = ((String) v).toLowerCase();
            boolean m = false;
            for (String sub : subs) if (s.contains(sub)) { m = true; break; }
            if (!m) continue;
            ReferenceIterator ri = rm.getReferencesTo(d.getAddress());
            while (ri.hasNext()) {
                Function f = fm.getFunctionContaining(ri.next().getFromAddress());
                if (f != null) hits.add(f);
            }
        }
        for (Function f : hits) {
            DecompileResults res = dec.decompileFunction(f, 60, monitor);
            if (res == null || !res.decompileCompleted()) continue;
            String nm = f.getName().replaceAll("[^A-Za-z0-9_]", "_");
            try (PrintWriter pw = new PrintWriter(new File(outdir, nm + ".c"))) {
                pw.print(res.getDecompiledFunction().getC());
            }
            println("wrote " + f.getName() + " @ " + f.getEntryPoint());
        }
        println("DumpStringXref: " + hits.size() + " functions");
    }
}

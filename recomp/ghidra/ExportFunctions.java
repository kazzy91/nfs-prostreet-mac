// ExportFunctions.java - Ghidra headless post-script for recomp/ghidra_functions.py: writes every function entry in
// executable memory of the analysed program, sorted, one per line as "<hex address>\t<name>". Arguments: the output path,
// then "rva" for addresses relative to the image base (default: virtual addresses). External (imported) functions have
// no code in the image and are left out; thunks (jmp [IAT] stubs) are real code and stay in.
//@category Export
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;

import java.io.PrintWriter;
import java.util.Map;
import java.util.TreeMap;

public class ExportFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new IllegalArgumentException("usage: ExportFunctions.java <out.tsv> [rva]");
        boolean rva = args.length > 1 && args[1].equals("rva");
        long base = currentProgram.getImageBase().getOffset();
        TreeMap<Long, String> functions = new TreeMap<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isExternal()) continue;
            MemoryBlock block = currentProgram.getMemory().getBlock(f.getEntryPoint());
            if (block == null || !block.isExecute()) continue;
            long a = f.getEntryPoint().getOffset();
            functions.put(rva ? a - base : a, f.getName());
        }
        try (PrintWriter w = new PrintWriter(args[0])) {
            for (Map.Entry<Long, String> e : functions.entrySet()) w.printf("%08X\t%s%n", e.getKey(), e.getValue());
        }
        println("ExportFunctions: " + functions.size() + " functions -> " + args[0]);
    }
}

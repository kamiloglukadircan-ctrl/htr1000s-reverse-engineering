// Ghidra headless post-script (Java GhidraScript)
// Finds crypto-related strings and lists functions that reference them.
//@category HTR1000S

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.Address;
import java.util.*;

public class FindSigVerify extends GhidraScript {

    String[] targets = new String[] {
        "pkcs1psssha256",
        "1.2.7.f-irdeto-flexiflash-v1",
        "IRDETO_UC_PRIVATE_DATA",
        "RSAPublicKey",
        "modulus",
        "exponent",
        "rootKeyHash",
        "packageSignature",
        "SignatureChain",
        "/var/lib/humaxtv/drm",
        "IRDETO_LOADER_PARTITION",
        "BCHP_BSP_GLB_CONTROL_FW_FLAGS"
    };

    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager refMgr = currentProgram.getReferenceManager();

        println("======================================================================");
        println("HTR-1000S / humaxtv crypto string xref hunt");
        println("======================================================================");

        for (String target : targets) {
            println("");
            println("----------------------------------------------------------------------");
            println("TARGET STRING: " + target);

            List<Address> hits = new ArrayList<>();
            DataIterator dataIter = listing.getDefinedData(true);
            while (dataIter.hasNext()) {
                Data data = dataIter.next();
                if (data.hasStringValue()) {
                    try {
                        Object val = data.getValue();
                        if (val != null && val.toString().contains(target)) {
                            hits.add(data.getAddress());
                        }
                    } catch (Exception e) {
                        // skip
                    }
                }
            }

            if (hits.isEmpty()) {
                println("  [not found as defined string data]");
                continue;
            }

            for (Address saddr : hits) {
                println("  String at: " + saddr);
                ReferenceIterator refs = refMgr.getReferencesTo(saddr);
                boolean foundRef = false;
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    foundRef = true;
                    Address fromAddr = ref.getFromAddress();
                    Function func = fm.getFunctionContaining(fromAddr);
                    if (func != null) {
                        println("    Referenced from " + fromAddr + " inside function "
                            + func.getName() + " @ " + func.getEntryPoint());
                    } else {
                        println("    Referenced from " + fromAddr + " (no containing function)");
                    }
                }
                if (!foundRef) {
                    println("    [no references to this string]");
                }
            }
        }

        println("");
        println("======================================================================");
        println("FUNCTIONS CONTAINING 'sig','verify','rsa','crypt','pkcs','sha','key' IN NAME");
        println("======================================================================");

        String[] keywords = new String[] {"sig", "verify", "rsa", "crypt", "pkcs", "sha", "key"};
        FunctionIterator fiter = fm.getFunctions(true);
        while (fiter.hasNext()) {
            Function f = fiter.next();
            String nm = f.getName().toLowerCase();
            for (String k : keywords) {
                if (nm.contains(k)) {
                    println("  " + f.getName() + " @ " + f.getEntryPoint()
                        + "  (size ~" + f.getBody().getNumAddresses() + " bytes)");
                    break;
                }
            }
        }

        println("");
        println("======================================================================");
        println("DONE");
        println("======================================================================");
    }
}

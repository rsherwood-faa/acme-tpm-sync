package gov.dot.faa.ang.idms.acmetpm.crypto.bridge;

import module java.base;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.lang.foreign.ValueLayout.*;

public final class CapiTpmBridge implements TpmCryptoBridge {
    private static final String DLL_PATH = "/native/windows-x86_64/TpmKeyHelper.dll";
    private static final Integer ERROR_BUFFER_SIZE = 1024;
    private static final Logger logger = LoggerFactory.getLogger(CapiTpmBridge.class);

    // Private Constructor to hide implicit
    private CapiTpmBridge() {}

    private static Path createTmpDllPath() throws IOException {
        try (var dllin = CapiTpmBridge.class.getResourceAsStream(DLL_PATH)) {
            if (dllin == null) {
                throw new IllegalStateException("Bundled CAPI dll not found.");
            }

            File tempDll;

            if(FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"));
                tempDll = Files.createTempFile("TpmKeyHelper", ".dll", attr).toFile();
            } else {
                tempDll = Files.createTempFile("TpmKeyHelper", ".dll").toFile();  // This is *literally* Sonarqube's suggested fix, which it is tagging as non-compliant
                if (!(tempDll.setReadable(true, true) && tempDll.setWritable(true, true))) {
                    throw new IOException("Unable to set file permissions safely for temporary file");
                }
            }
            tempDll.deleteOnExit();

            var tempDllPath = tempDll.toPath();
            Files.copy(dllin, tempDllPath, StandardCopyOption.REPLACE_EXISTING);
            return tempDllPath;   
        }
    }

    public static void generateTpmKey(String alias, String container, String subjectDn) throws Throwable {
        if(!System.getProperty("os.name").toLowerCase().contains("win")) {
            throw new UnsupportedOperationException("CAPI key generation only works on windows.");
        }

        var tmpDllPath = createTmpDllPath();

        try (var arena = Arena.ofConfined()) {
            var lib = SymbolLookup.libraryLookup(tmpDllPath, arena);
            var generateFunction = Linker.nativeLinker().downcallHandle(
                lib.findOrThrow("generate_tpm_key"), 
                FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS,ADDRESS,ADDRESS,JAVA_INT)
            );

            MemorySegment aliasSeg = arena.allocateFrom(alias, StandardCharsets.UTF_16LE);
            MemorySegment containerSeg = arena.allocateFrom(container, StandardCharsets.UTF_16LE);
            MemorySegment subjectSeg = arena.allocateFrom(subjectDn, StandardCharsets.UTF_16LE);

            MemorySegment errorBuffer = arena.allocate(ERROR_BUFFER_SIZE);

            int returnCode = (int) generateFunction.invokeExact(aliasSeg, containerSeg, subjectSeg, errorBuffer, ERROR_BUFFER_SIZE.intValue());

            if (returnCode != 0) {
                String errorDetails = errorBuffer.getString(0, StandardCharsets.UTF_8);
                throw new IllegalStateException("TPM Key Generation failed (code " + returnCode + "): " + errorDetails);
            } else {
                logger.info("Successfully generated TPM key with alias '{}' in container '{}'", alias, container);
                String errorDetails = errorBuffer.getString(0, StandardCharsets.UTF_8);
                if (!errorDetails.isEmpty()) {
                    logger.warn("TPM Key Generation returned warnings: {}", errorDetails);
                }
            }
        } finally {
            try {
                Files.deleteIfExists(tmpDllPath);
            } catch (AccessDeniedException e) {
                logger.warn("Unable to immediately delete temporary native library {}; deletion is deferred to JVM exit", tmpDllPath);
            }
        }
    }
}

package org.owasp.dependencycheck.analyzer;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.dart.PubSpecLock;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.representer.Representer;

import java.io.*;

//@ThreadSafe
@Experimental
public class PubPackageAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.DART;

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(PubPackageAnalyzer.class);

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Dart Pub Package Analyzer";

    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

    /**
     * The file name to scan.
     */
    public static final String PUBSPEC_LOCK = "pubspec.lock";

    /**
     * The file name to scan.
     */
    public static final String PACKAGE_CONFIG = "package_config.json";

    @Override
    protected FileFilter getFileFilter() {
        return FileFilterBuilder.newInstance().addFilenames(PUBSPEC_LOCK).build();
    }

    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        // TODO: Figure out what to do here
    }

    @Override
    public String getName() {
        return ANALYZER_NAME;
    }

    @Override
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }

    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_PUB_ENABLED;
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        try {
            analyzePubFileDependency(dependency, engine);
        } catch(IOException ex) {
            throw new AnalysisException("Error reading the pub file while analyzing '" + dependency.getFilePath() + "'", ex);
        }
    }

    private void analyzePubFileDependency(Dependency dependency, Engine engine) throws IOException {
        dependency.setEcosystem(DEPENDENCY_ECOSYSTEM);

        InputStream inputStream = new FileInputStream(dependency.getActualFile());

        Representer representer = new Representer();
        representer.getPropertyUtils().setSkipMissingProperties(true);

        Yaml yaml = new Yaml(new Constructor(PubSpecLock.class), representer);
        PubSpecLock data = yaml.load(inputStream);

        data.getPackages().forEach((name, pkg) -> {
            Dependency dep = createVirtualDependency(dependency, name, pkg.getVersion(), "dart");
            engine.addDependency(dep);
        });

        // TODO: Replace this with the parsed flutter and dart versions
        dependency.addEvidence(EvidenceType.VENDOR, PUBSPEC_LOCK, "name", "dart", Confidence.HIGH);
        dependency.addEvidence(EvidenceType.PRODUCT, PUBSPEC_LOCK, "name", "dart_software_development_kit", Confidence.HIGHEST);
        dependency.addEvidence(EvidenceType.VERSION, PUBSPEC_LOCK, "version", "2.0.0", Confidence.HIGHEST);
    }
    /**
     * Builds a dependency object based on the given data.
     *
     * @param parentDependency a reference to the parent dependency
     * @param name the name of the dependency
     * @param version the version of the dependency
     * @param vendor the vendor of the dependency
     * @return a new dependency object
     */
    private Dependency createVirtualDependency(Dependency parentDependency, String name, String version, String vendor) {
        final Dependency dep = new Dependency(parentDependency.getActualFile(), true);
        // TODO: Solve for some dependencies that have an unknown vendor but the targetSw is `dart`
        //  ex: cpe:2.3:a:flutterchina:dio:4.0.0:*:*:*:*:dart:*:*
        //  ex: cpe:2.3:a:grpc:grpc:1.24.2:*:*:*:*:dart:*:*
        /*
            try {
                Cpe cpe = new Cpe(Part.APPLICATION, "*", name, version, "*", "*", "*", "*", "dart", "*", "*");
                CpeIdentifier cpeIden = new CpeIdentifier(cpe, Confidence.HIGH);
                dep.addSoftwareIdentifier(cpeIden);
            } catch (CpeValidationException e) {
                e.printStackTrace();
            }
        */

        dep.setEcosystem(DEPENDENCY_ECOSYSTEM);
        dep.addEvidence(EvidenceType.VENDOR, PUBSPEC_LOCK, "name", vendor, Confidence.HIGH);
        dep.addEvidence(EvidenceType.PRODUCT, PUBSPEC_LOCK, "name", name, Confidence.HIGHEST);
        dep.addEvidence(EvidenceType.VERSION, PUBSPEC_LOCK, "version", version, Confidence.HIGHEST);
        dep.setName(name);
        dep.setVersion(version);
        dep.setDisplayFileName(name);
        dep.setPackagePath(parentDependency.getActualFilePath());

        try {
            // TODO: Would `pub` or `dart` be the ecosystem for the pkg?
            final PackageURL purl = PackageURLBuilder.aPackageURL()
                    .withType("pub")
                    .withName(name)
                    .withVersion(version)
                    .build();
            final PurlIdentifier id = new PurlIdentifier(purl, Confidence.HIGHEST);
            dep.addSoftwareIdentifier(id);

            dep.setSha1sum(Checksum.getSHA1Checksum(id.toString()));
            dep.setMd5sum(Checksum.getMD5Checksum(id.toString()));
            dep.setSha256sum(Checksum.getSHA256Checksum(id.toString()));
        } catch (MalformedPackageURLException ex) {
            LOGGER.debug("Unable to build package url", ex);
        }

        return dep;
    }

}

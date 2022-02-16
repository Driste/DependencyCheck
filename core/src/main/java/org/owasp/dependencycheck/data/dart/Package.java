package org.owasp.dependencycheck.data.dart;

public class Package {
    public String dependency;
    public String source;
    public String version;

    public String getDependency() {
        return dependency;
    }
    public void setDependency(String dependency) {
        this.dependency = dependency;
    }

    public String getSource() {
        return source;
    }
    public void getSource(String source) {
        this.source = source;
    }

    public String getVersion() {
        return version;
    }
    public void setVersion(String version) {
        this.version = version;
    }
}

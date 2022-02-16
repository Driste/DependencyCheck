package org.owasp.dependencycheck.data.dart;

import java.util.Map;

public class PubSpecLock {
    public Map<String, Package> packages;
    public Map<String, String> sdks;

    public Map<String, Package> getPackages() {
        return packages;
    }

    public void setPackages(Map<String, Package> packages) {
        this.packages = packages;
    }

    public Map<String, String> getSdks() {
        return sdks;
    }

    public void setSdks(Map<String, String> sdks) {
        this.sdks = sdks;
    }
}




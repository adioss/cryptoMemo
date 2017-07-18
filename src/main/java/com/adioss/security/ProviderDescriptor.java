package com.adioss.security;

import java.security.Provider;
import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.security.jca.ProviderList;
import sun.security.jca.Providers;

public class ProviderDescriptor {
    private static final Logger LOG = LoggerFactory.getLogger(ProviderDescriptor.class);

    private static void showProviderDescriptor() {
        ProviderList fullProviderList = Providers.getFullProviderList();
        List<Provider> providers = fullProviderList.providers();
        for (Provider provider : providers) {
            LOG.debug(String.format(">>>>>>>>>>>>>>>  Provider: %s%n", provider.getName()));
            LOG.debug(String.format(">>>>>>  Info: %s%n", provider.getInfo()));
            LOG.debug(String.format(">>>>>>  Version: %s%n", provider.getVersion()));
            Set<Provider.Service> services = provider.getServices();
            for (Provider.Service service : services) {
                LOG.debug(String.format("Algo: %s for Type: %s%n", service.getAlgorithm(), service.getType()));
            }
            LOG.debug("<<<<<<<<<<<<<<<");
        }
    }

    private ProviderDescriptor() {
    }

    public static void main(String... args) {
        showProviderDescriptor();
    }
}

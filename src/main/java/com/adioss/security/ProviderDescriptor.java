package com.adioss.security;

import java.security.Provider;
import java.util.*;
import sun.security.jca.ProviderList;
import sun.security.jca.Providers;

public class ProviderDescriptor {
    public static void main(String... args) {
        ProviderList fullProviderList = Providers.getFullProviderList();
        List<Provider> providers = fullProviderList.providers();
        for (Provider provider : providers) {
            System.out.printf(">>>>>>>>>>>>>>>  Provider: %s%n", provider.getName());
            System.out.printf(">>>>>>  Info: %s%n", provider.getInfo());
            System.out.printf(">>>>>>  Version: %s%n", provider.getVersion());
            Set<Provider.Service> services = provider.getServices();
            for (Provider.Service service : services) {

                System.out.printf("Algo: %s for Type: %s%n", service.getAlgorithm(), service.getType());
            }
            System.out.println("<<<<<<<<<<<<<<<");
        }
    }

    private ProviderDescriptor() {
    }
}
